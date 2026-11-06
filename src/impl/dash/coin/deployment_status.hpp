// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

/// Dash Core v24 deployment status: is DEPLOYMENT_V24 (or EVO_SHARES) active
/// for the block at a height, and which block version signals for it.
///
/// This is the switch every v24 rule keys on. Core's predicate is
/// DeploymentActiveAfter(pindexPrev, DEPLOYMENT_V24), i.e. the versionbits
/// state of the block's PARENT (validation.cpp GetSpecialTxRules). Here:
///
///   v24_state(height) -> ACTIVE / INACTIVE / UNKNOWN for the block at height
///   v24_active(net, height)  the S2 hook: true only when ACTIVE is proven
///   block_version(height)    ComputeBlockVersion for the block at height
///
/// How a height is decided, in order:
///   1. Buried height (testnet 1,578,000: history, proven by the replay KAT).
///   2. Exact: the EHF tracker has scanned every body from its anchor to the
///      parent, so SignalHeight is known and the versionbits machine runs on
///      real data.
///   3. Bound: bodies are missing, but the headers alone bound the answer. An
///      earlier EHF signal can only bring activation earlier (a lower attempt
///      number means a higher threshold), so the machine run with the signal
///      at height 0 gives the EARLIEST possible state. If even that is not
///      ACTIVE, the block is proven INACTIVE. Otherwise UNKNOWN.
///   4. Heights past the header tip: the state of the next block's period
///      bounds the following periods (DEFINED needs three more periods to
///      reach ACTIVE, STARTED two, LOCKED_IN exactly one).
/// UNKNOWN is never folded into "inactive" by this file: v24_active() is
/// false for it (the S2 hook semantics), and callers that build or fold
/// consensus data must ask v24_state() and fail closed on UNKNOWN.
///
/// Emergency override (operator decision O7): --dash-v24-activation-height N
/// pins activation at N (a period boundary). It decides only where the
/// computation is UNKNOWN; where the computation is decided and disagrees
/// with the pin, the answer is UNKNOWN (fail closed, logged once).

#include <impl/dash/coin/dash_deployments.hpp>
#include <impl/dash/coin/ehf_tracker.hpp>
#include <impl/dash/coin/versionbits.hpp>

#include <core/log.hpp>

#include <array>
#include <atomic>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <string>

namespace dash {
namespace coin {

enum class V24State : uint8_t { INACTIVE, ACTIVE, UNKNOWN };

inline const char* v24_state_name(V24State s)
{
    switch (s) {
    case V24State::INACTIVE: return "inactive";
    case V24State::ACTIVE:   return "active";
    case V24State::UNKNOWN:  return "unknown";
    }
    return "?";
}

/// The result of resolving one deployment for one block.
struct DeploymentResolution
{
    std::optional<ThresholdState> state;   ///< exact state, when known
    V24State active{V24State::UNKNOWN};    ///< ACTIVE / INACTIVE / UNKNOWN
    const char* basis{"unknown"};          ///< buried / exact / bound / override / unknown
};

/// Validate an operator activation pin: it must be a period boundary (Core
/// activates only at the first block of a period) and not below the earliest
/// activation the parameters allow. Returns an error text, or empty.
inline std::string validate_v24_activation_pin(DashNetwork net, int64_t pin)
{
    const auto& p = dash_deployment_params(net);
    const int64_t P = vb_period(p, p.dep(DashDeployment::V24));
    if (pin <= 0) return "must be a positive height";
    if (pin % P != 0)
        return "must be a multiple of the " + std::to_string(P) + "-block window (activation is at a period start)";
    // Activation needs at least STARTED and LOCKED_IN periods before it.
    if (pin < 2 * P) return "is below the earliest possible activation";
    return {};
}

class DashDeploymentStatus
{
public:
    /// `chain`: active-chain headers by height. `tip_height`: the header tip
    /// (nullopt while there is none). `ehf`: the signal tracker (may be null:
    /// then nothing is exact and the status works from bounds only).
    DashDeploymentStatus(DashNetwork net, VbChainFn chain,
                         std::function<std::optional<uint32_t>()> tip_height,
                         std::shared_ptr<const EhfSignalTracker> ehf)
        : DashDeploymentStatus(dash_deployment_params(net), std::move(chain),
                               std::move(tip_height), std::move(ehf))
    {}
    /// `params` must outlive the status (the static table does).
    DashDeploymentStatus(const DashDeploymentParams& params, VbChainFn chain,
                         std::function<std::optional<uint32_t>()> tip_height,
                         std::shared_ptr<const EhfSignalTracker> ehf)
        : m_params(params),
          m_chain(chain),
          m_tip(std::move(tip_height)),
          m_ehf(std::move(ehf)),
          m_exact{VersionBitsChecker(m_params, DashDeployment::V24, chain),
                  VersionBitsChecker(m_params, DashDeployment::EVO_SHARES, chain)},
          m_bound{VersionBitsChecker(m_params, DashDeployment::V24, chain),
                  VersionBitsChecker(m_params, DashDeployment::EVO_SHARES, chain)}
    {}

    DashNetwork network() const { return m_params.network; }
    const DashDeploymentParams& params() const { return m_params; }

    void set_v24_activation_override(std::optional<uint32_t> pin) { m_pin = pin; }
    std::optional<uint32_t> v24_activation_override() const { return m_pin; }

    /// Resolve a deployment for the block at `height` (parent height - 1).
    DeploymentResolution resolve(uint32_t height, DashDeployment dep)
    {
        DeploymentResolution r = compute(height, dep);
        if (dep != DashDeployment::V24 || !m_pin) return r;
        const V24State pinned = height >= *m_pin ? V24State::ACTIVE : V24State::INACTIVE;
        if (r.active == V24State::UNKNOWN) {
            r.active = pinned;
            r.basis = "override";
            return r;
        }
        if (r.active != pinned) {
            if (!m_pin_conflict_logged.exchange(true))
                LOG_ERROR << "[DASH-V24] --dash-v24-activation-height=" << *m_pin
                          << " CONTRADICTS the computed v24 state at h=" << height
                          << " (" << v24_state_name(r.active) << ", " << r.basis
                          << "): v24 state is UNKNOWN, the embedded arm fails closed";
            r.active = V24State::UNKNOWN;
            r.basis = "override-conflict";
        }
        return r;
    }

    V24State v24_state(uint32_t height) { return resolve(height, DashDeployment::V24).active; }
    bool v24_active(uint32_t height) { return v24_state(height) == V24State::ACTIVE; }

    /// ComputeBlockVersion for the block at `height`: the top bits plus the
    /// bit of every deployment that is STARTED or LOCKED_IN for it (both have
    /// gbt_force, so Core's GBT keeps them). A deployment whose state is not
    /// known exactly contributes no bit: signalling is not consensus, and an
    /// unproven signal is simply omitted (design §3.1 item 7).
    uint32_t block_version(uint32_t height)
    {
        uint32_t v = static_cast<uint32_t>(kVersionBitsTopBits);
        for (int i = 0; i < kDashDeploymentCount; ++i) {
            const auto dep = static_cast<DashDeployment>(i);
            const auto r = compute(height, dep);
            if (r.state && (*r.state == ThresholdState::STARTED || *r.state == ThresholdState::LOCKED_IN))
                v |= m_params.dep(dep).mask();
        }
        return v;
    }

    /// The activation height of a deployment once it is known from the chain
    /// (LOCKED_IN or ACTIVE at the tip), or the buried height.
    std::optional<uint32_t> activation_height(DashDeployment dep)
    {
        if (dep == DashDeployment::V24 && m_params.v24_buried_height) return m_params.v24_buried_height;
        const auto tip = m_tip();
        if (!tip) return std::nullopt;
        const auto r = compute(*tip + 1, dep);
        if (!r.state) return std::nullopt;
        const int64_t P = vb_period(m_params, m_params.dep(dep));
        const int64_t prev = static_cast<int64_t>(*tip);
        if (*r.state == ThresholdState::LOCKED_IN) {
            const int64_t period_start = prev + 1 - ((prev + 1) % P);
            return static_cast<uint32_t>(period_start + P);
        }
        if (*r.state == ThresholdState::ACTIVE) {
            const int64_t sh = signal_height_for(dep, prev);
            auto since = m_exact[static_cast<int>(dep)].state_since_height(prev, sh);
            if (since) return static_cast<uint32_t>(*since);
        }
        return std::nullopt;
    }

    /// Signalling statistics of the period containing `height` (exact only).
    std::optional<VbStats> statistics(uint32_t height, DashDeployment dep)
    {
        if (!exact_known(static_cast<int64_t>(height))) return std::nullopt;
        return m_exact[static_cast<int>(dep)].statistics(height, signal_height_for(dep, height));
    }

private:
    bool exact_known(int64_t prev_height) const
    {
        const bool use_ehf = true;   // both deployments are EHF
        if (!use_ehf) return true;
        return m_ehf && m_ehf->covers(prev_height);
    }

    int64_t signal_height_for(DashDeployment dep, int64_t prev_height) const
    {
        const auto& d = m_params.dep(dep);
        if (!d.useEHF) return 0;
        // GetSignalsStage is empty before V20.
        if (prev_height + 1 < static_cast<int64_t>(m_params.v20_height)) return kNoSignalHeight;
        if (!m_ehf) return kNoSignalHeight;
        return m_ehf->signal_height(static_cast<uint8_t>(d.bit), prev_height);
    }

    static V24State from_state(ThresholdState s)
    {
        return s == ThresholdState::ACTIVE ? V24State::ACTIVE : V24State::INACTIVE;
    }

    DeploymentResolution compute(uint32_t height, DashDeployment dep)
    {
        DeploymentResolution r;
        const int idx = static_cast<int>(dep);
        const int64_t prev = static_cast<int64_t>(height) - 1;

        if (dep == DashDeployment::V24 && m_params.v24_buried_height) {
            r.active = height >= *m_params.v24_buried_height ? V24State::ACTIVE : V24State::INACTIVE;
            r.state = r.active == V24State::ACTIVE ? std::optional<ThresholdState>(ThresholdState::ACTIVE)
                                                   : std::nullopt;
            r.basis = "buried";
            return r;
        }

        const auto tip = m_tip();
        if (tip && prev > static_cast<int64_t>(*tip)) return beyond_tip(height, dep, *tip);
        if (!tip && prev >= 0) {
            r.basis = "no-headers";
            return r;
        }

        if (exact_known(prev)) {
            const auto s = m_exact[idx].state_for(prev, signal_height_for(dep, prev));
            if (s) {
                r.state = s;
                r.active = from_state(*s);
                r.basis = "exact";
                return r;
            }
            r.basis = "headers-missing";
            return r;
        }
        // Bound: the signal at height 0 gives the earliest possible state.
        const auto earliest = m_bound[idx].state_for(prev, 0);
        if (earliest && (*earliest == ThresholdState::DEFINED || *earliest == ThresholdState::STARTED
                         || *earliest == ThresholdState::LOCKED_IN)) {
            r.active = V24State::INACTIVE;
            r.basis = "bound";
            return r;
        }
        r.basis = earliest ? "ehf-scan-incomplete" : "headers-missing";
        return r;
    }

    /// A block past the header tip: bound it from the next block's period.
    DeploymentResolution beyond_tip(uint32_t height, DashDeployment dep, uint32_t tip)
    {
        DeploymentResolution r;
        const auto next = compute(tip + 1, dep);
        const int64_t P = vb_period(m_params, m_params.dep(dep));
        const int64_t next_h = static_cast<int64_t>(tip) + 1;
        const int64_t next_period = next_h - (next_h % P);
        const int64_t periods_ahead = (static_cast<int64_t>(height) - next_period) / P;
        if (next.active == V24State::ACTIVE) {
            r.active = V24State::ACTIVE;
            r.basis = "beyond-tip";
            return r;
        }
        if (!next.state) {
            // Inactive by bound or unknown: a bound only carries for its own
            // period (the earliest machine may lock in at the next boundary).
            if (next.active == V24State::INACTIVE && periods_ahead < 1) {
                r.active = V24State::INACTIVE;
                r.basis = "beyond-tip";
            }
            return r;
        }
        int64_t needed = 0;   // periods after the next block's period before ACTIVE is possible
        switch (*next.state) {
        case ThresholdState::DEFINED:   needed = 3; break;
        case ThresholdState::STARTED:   needed = 2; break;
        case ThresholdState::LOCKED_IN: needed = 1; break;
        case ThresholdState::FAILED:    r.active = V24State::INACTIVE; r.basis = "beyond-tip"; return r;
        case ThresholdState::ACTIVE:    r.active = V24State::ACTIVE;   r.basis = "beyond-tip"; return r;
        }
        if (*next.state == ThresholdState::LOCKED_IN) {
            r.active = periods_ahead >= 1 ? V24State::ACTIVE : V24State::INACTIVE;
            r.basis = "beyond-tip";
            return r;
        }
        if (periods_ahead < needed) {
            r.active = V24State::INACTIVE;
            r.basis = "beyond-tip";
        }
        return r;
    }

    const DashDeploymentParams& m_params;
    VbChainFn m_chain;
    std::function<std::optional<uint32_t>()> m_tip;
    std::shared_ptr<const EhfSignalTracker> m_ehf;
    std::array<VersionBitsChecker, kDashDeploymentCount> m_exact;
    std::array<VersionBitsChecker, kDashDeploymentCount> m_bound;
    std::optional<uint32_t> m_pin;
    std::atomic<bool> m_pin_conflict_logged{false};
};

// ── Process-wide registry and the S2 hook ───────────────────────────────────
//
// The node installs one DashDeploymentStatus for the network it runs; code
// that has only a network and a height (codecs, folds) asks through the free
// functions below. With no status installed (unit tests, tools) the answer is
// the buried height where one exists, the operator pin when one is set, and
// otherwise INACTIVE below the network's earliest possible activation and
// UNKNOWN from it on.

namespace deployment_registry_detail {
struct Registry
{
    std::mutex m;
    std::shared_ptr<DashDeploymentStatus> status[4];
    std::optional<uint32_t> pin[4];
};
inline Registry& registry()
{
    static Registry r;
    return r;
}
} // namespace deployment_registry_detail

inline void install_dash_deployment_status(DashNetwork net, std::shared_ptr<DashDeploymentStatus> st)
{
    auto& r = deployment_registry_detail::registry();
    std::lock_guard<std::mutex> lk(r.m);
    r.status[static_cast<int>(net)] = std::move(st);
}

inline std::shared_ptr<DashDeploymentStatus> dash_deployment_status(DashNetwork net)
{
    auto& r = deployment_registry_detail::registry();
    std::lock_guard<std::mutex> lk(r.m);
    return r.status[static_cast<int>(net)];
}

/// The operator pin for a network without an installed status (the status
/// carries its own copy, set by the node from the same flag).
inline void set_dash_v24_activation_pin(DashNetwork net, std::optional<uint32_t> pin)
{
    auto& r = deployment_registry_detail::registry();
    std::lock_guard<std::mutex> lk(r.m);
    r.pin[static_cast<int>(net)] = pin;
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

/// DeploymentActiveAfter(pindexPrev, DEPLOYMENT_V24) for the block at
/// `height`, tri-state. Fail closed on UNKNOWN.
inline V24State v24_state(DashNetwork net, uint32_t height)
{
    if (auto st = dash_deployment_status(net)) return st->v24_state(height);
    const auto& p = dash_deployment_params(net);
    if (p.v24_buried_height) return height >= *p.v24_buried_height ? V24State::ACTIVE : V24State::INACTIVE;
    std::optional<uint32_t> pin;
    {
        auto& r = deployment_registry_detail::registry();
        std::lock_guard<std::mutex> lk(r.m);
        pin = r.pin[static_cast<int>(net)];
    }
    if (pin) return height >= *pin ? V24State::ACTIVE : V24State::INACTIVE;
    return height < v24_earliest_unmeasured_activation(net) ? V24State::INACTIVE : V24State::UNKNOWN;
}

/// The S2 hook (v24_rules.hpp): true only when V24 is proven active for the
/// block at `height`.
inline bool v24_active(DashNetwork net, uint32_t height)
{
    return v24_state(net, height) == V24State::ACTIVE;
}

} // namespace coin
} // namespace dash
