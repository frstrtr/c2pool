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
///   2. Exact: SignalHeight(parent) is decided by the scanned bodies, so the
///      versionbits machine runs on real data. That holds when the tracker
///      covers the parent, but also when it covers less: c = the verified
///      coverage (every body in [anchor, c] scanned and still on the chain).
///        - A signal for the bit at or below c is final: a later one cannot be
///          lower, and Core refuses a second one (bad-mnhf-duplicate).
///        - With no signal at or below c, S > c. The state of a block depends
///          on S only at period ends (E >= S), so if no period end lies in
///          (c, parent], S is "no signal" for it.
///      So the state of the block after the tip is decided before the tip's
///      own body is scanned (after activation always; before it, except for
///      the first block of a period). VERIFY-H0-S0-S1 M3.
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
///
/// Live cross-check (design §3.1 item 8; VERIFY-H0-S0-S1 M2): Dash Core v24
/// requires CbTx version 4 exactly when v24 is active, so every block on our
/// chain states the switch. cross_check_cbtx_version() compares it with our
/// answer for that block. A contradiction latches the status:
///   - our exact (tracker-derived) answer was refuted: from then on only the
///     header-only bound (proven INACTIVE) is trusted, everything else is
///     UNKNOWN;
///   - the bound itself was refuted: everything but a buried height is
///     UNKNOWN;
///   - the pin was the answer refuted: the pin is ignored.
/// The embedded arm then declines (v24-state-unknown) and the dashd v24 arm or
/// a correct pin serves. The latch clears only on restart, or when a later
/// cross-check finds the recomputed answer agreeing with the chain both at
/// the latched block and at the new one.

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
#include <sstream>
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
    const char* basis{"unknown"};          ///< buried / exact / bound / override / unknown / ...
};

/// Outcome of one live cross-check.
enum class V24CrossCheck : uint8_t
{
    AGREE,         ///< our decided answer matches the chain's CbTx version
    CONTRADICTS,   ///< it does not: the status is latched (see above)
    UNDECIDED,     ///< nothing to compare (UNKNOWN, or not our chain's block)
};

/// What a contradiction refuted (the latch level).
enum class V24Latch : uint8_t { NONE, EXACT, BOUND };

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

    void set_v24_activation_override(std::optional<uint32_t> pin)
    {
        std::lock_guard<std::mutex> lk(m_latch_mutex);
        m_pin = pin;
        m_pin_refuted = false;
    }
    std::optional<uint32_t> v24_activation_override() const
    {
        std::lock_guard<std::mutex> lk(m_latch_mutex);
        return m_pin;
    }

    /// Stop answering from the chain view (teardown: the header chain the
    /// chain function reads may be gone). Every answer is UNKNOWN after this.
    void shutdown() { m_closed.store(true); }

    /// Resolve a deployment for the block at `height` (parent height - 1).
    DeploymentResolution resolve(uint32_t height, DashDeployment dep)
    {
        if (m_closed.load()) return DeploymentResolution{std::nullopt, V24State::UNKNOWN, "shutdown"};
        V24Latch latch;
        std::optional<uint32_t> pin;
        {
            std::lock_guard<std::mutex> lk(m_latch_mutex);
            latch = m_latch;
            if (!m_pin_refuted) pin = m_pin;
        }
        DeploymentResolution r = compute(height, dep);
        if (dep == DashDeployment::V24) r = apply_latch(height, dep, r, latch);
        if (dep != DashDeployment::V24 || !pin) return r;
        return apply_pin(r, height, *pin);
    }

    /// The live cross-check for the block at `height` whose hash is
    /// `block_hash` and whose CbTx payload version is `cbtx_version` (Dash
    /// Core v24 CheckCbTx: 4 exactly when v24 is active). Only a block the
    /// chain view holds at that height is compared.
    V24CrossCheck cross_check_cbtx_version(uint32_t height, const uint256& block_hash,
                                           uint16_t cbtx_version)
    {
        if (m_closed.load()) return V24CrossCheck::UNDECIDED;
        if (m_params.v24_buried_height) return V24CrossCheck::UNDECIDED;   // history
        revalidate_latch();
        {
            auto b = m_chain(height);
            if (!b || b->hash != block_hash) return V24CrossCheck::UNDECIDED;
        }
        // A CbTx version Dash Core rejects whatever the v24 state (CheckCbTx:
        // 0 or 5+, below 3 from V20 on, 3+ before V20) agrees with no answer:
        // latch at the bound level (everything but a buried height UNKNOWN).
        // Only this block leaving our best chain clears it.
        if (cbtx_version_invalid(height, cbtx_version)) {
            uint64_t n = 0;
            {
                std::lock_guard<std::mutex> lk(m_latch_mutex);
                m_latch = V24Latch::BOUND;
                m_latch_height = height;
                m_latch_hash = block_hash;
                m_latch_chain_active = cbtx_version >= 4;
                m_latch_invalid_version = true;
                ++m_latch_version;
                n = ++m_contradictions;
            }
            if (n <= 3 || (n % 100) == 0)
                LOG_ERROR << "[DASH-V24] CROSS-CHECK FAILED h=" << height << " "
                          << block_hash.GetHex().substr(0, 16) << ": CbTx version " << cbtx_version
                          << " is one Dash Core rejects at this height (bad-cbtx-version) -- v24 state LATCHED"
                             " UNKNOWN until this block leaves our best chain; the embedded arm fails closed"
                             " (v24-state-unknown). contradictions="
                          << n;
            return V24CrossCheck::CONTRADICTS;
        }
        const bool chain_active = cbtx_version >= 4;
        maybe_clear_latch(height, chain_active);
        DeploymentResolution r = resolve(height, DashDeployment::V24);
        if (r.active == V24State::UNKNOWN) return V24CrossCheck::UNDECIDED;
        if ((r.active == V24State::ACTIVE) == chain_active) return V24CrossCheck::AGREE;
        // Contradiction. Latch what was refuted, then re-resolve: the answer
        // the latch falls back to may be refuted by the same block (the bound
        // under a refuted exact answer), so escalate until nothing decided
        // contradicts this block.
        uint64_t n = 0;
        for (int round = 0; round < 3; ++round) {
            const std::string basis = r.basis;
            V24Latch level = V24Latch::NONE;
            bool pin_refuted = false;
            if (basis == "override") pin_refuted = true;
            else if (basis == "bound" || basis == "beyond-tip") level = V24Latch::BOUND;
            else level = V24Latch::EXACT;   // exact (or anything tracker-derived)
            {
                std::lock_guard<std::mutex> lk(m_latch_mutex);
                if (pin_refuted) m_pin_refuted = true;
                if (level > m_latch) m_latch = level;
                ++m_latch_version;
                if (level != V24Latch::NONE) {
                    m_latch_height = height;
                    m_latch_hash = block_hash;
                    m_latch_chain_active = chain_active;
                    m_latch_invalid_version = false;
                }
                if (round == 0) n = ++m_contradictions;
            }
            if (n <= 3 || (n % 100) == 0)
                LOG_ERROR << "[DASH-V24] CROSS-CHECK FAILED h=" << height << " "
                          << block_hash.GetHex().substr(0, 16) << ": our v24 state is "
                          << v24_state_name(r.active) << " (" << basis
                          << ") but the chain's CbTx version is " << cbtx_version
                          << " (Dash Core v24 requires 4 exactly when v24 is active) -- "
                          << (pin_refuted ? "the --dash-v24-activation-height pin is wrong and is now IGNORED"
                                          : level == V24Latch::BOUND
                                                ? "even the header-only bound is wrong: v24 state LATCHED UNKNOWN"
                                                : "the EHF-derived state is wrong: v24 state LATCHED to the header-only bound")
                          << "; the embedded arm fails closed (v24-state-unknown). contradictions=" << n;
            r = resolve(height, DashDeployment::V24);
            if (r.active == V24State::UNKNOWN || (r.active == V24State::ACTIVE) == chain_active) break;
        }
        return V24CrossCheck::CONTRADICTS;
    }

    V24Latch latch() const
    {
        std::lock_guard<std::mutex> lk(m_latch_mutex);
        return m_latch;
    }
    bool pin_refuted() const
    {
        std::lock_guard<std::mutex> lk(m_latch_mutex);
        return m_pin_refuted;
    }
    uint64_t contradictions() const
    {
        std::lock_guard<std::mutex> lk(m_latch_mutex);
        return m_contradictions;
    }

    /// Bumped on every latch change (set, escalate, clear): the node persists
    /// the latch when this moves (VERIFY-H0-S0-S1 N6).
    uint64_t latch_version() const
    {
        std::lock_guard<std::mutex> lk(m_latch_mutex);
        return m_latch_version;
    }

    /// The latch as a small text record (v24_latch.v1), and back. A restart
    /// keeps a refuted state refuted instead of serving it again until the
    /// next connected block re-latches it. Only for the same network.
    /// v2 adds the latched block's hash and whether its CbTx version was one
    /// Core rejects, so a restart can tell whether that block is still on our
    /// best chain (revalidate_latch). v1 records (no hash) still load.
    std::string serialize_latch() const
    {
        std::lock_guard<std::mutex> lk(m_latch_mutex);
        return "v24_latch v2 " + std::to_string(static_cast<int>(m_params.network)) + " "
             + std::to_string(static_cast<int>(m_latch)) + " " + std::to_string(m_latch_height) + " "
             + (m_latch_chain_active ? "1" : "0") + " " + (m_pin_refuted ? "1" : "0") + " "
             + std::to_string(m_pin.value_or(0)) + " " + std::to_string(m_contradictions) + " "
             + (m_latch_hash.IsNull() ? std::string("-") : m_latch_hash.GetHex()) + " "
             + (m_latch_invalid_version ? "1" : "0") + "\n";
    }
    bool deserialize_latch(const std::string& text)
    {
        std::istringstream in(text);
        std::string tag, ver;
        int net = -1, level = -1, active = 0, pin = 0;
        uint32_t h = 0, pin_height = 0;
        uint64_t n = 0;
        if (!(in >> tag >> ver >> net >> level >> h >> active >> pin >> pin_height >> n)) return false;
        if (tag != "v24_latch" || (ver != "v1" && ver != "v2") || net != static_cast<int>(m_params.network))
            return false;
        if (level < 0 || level > static_cast<int>(V24Latch::BOUND)) return false;
        uint256 hash;
        int invalid = 0;
        if (ver == "v2") {
            std::string hex;
            if (!(in >> hex >> invalid)) return false;
            if (hex != "-") {
                if (hex.size() != 64 || hex.find_first_not_of("0123456789abcdef") != std::string::npos)
                    return false;
                hash.SetHex(hex);
            }
        }
        std::lock_guard<std::mutex> lk(m_latch_mutex);
        m_latch = static_cast<V24Latch>(level);
        m_latch_height = h;
        m_latch_hash = hash;
        m_latch_invalid_version = invalid != 0;
        m_latch_chain_active = active != 0;
        // A refuted pin stays refuted only while it is the same pin: the node
        // sets the pin before loading, and a changed pin is a new operator
        // decision.
        m_pin_refuted = pin != 0 && m_pin && *m_pin == pin_height;
        m_contradictions = n;
        return true;
    }

private:
    /// The answer under a cross-check latch: a buried height stands; with
    /// the exact path refuted, only the header-only bound (proven INACTIVE)
    /// stands; with the bound refuted too, nothing does.
    DeploymentResolution apply_latch(uint32_t height, DashDeployment dep,
                                     const DeploymentResolution& r, V24Latch latch)
    {
        if (latch == V24Latch::NONE || std::string(r.basis) == "buried") return r;
        DeploymentResolution out;
        out.basis = "cross-check-latch";
        if (latch == V24Latch::EXACT) {
            const auto tip = m_tip();
            const int64_t prev = static_cast<int64_t>(height) - 1;
            if (tip && prev <= static_cast<int64_t>(*tip)) {
                const auto earliest = m_bound[static_cast<int>(dep)].state_for(prev, 0);
                if (earliest && (*earliest == ThresholdState::DEFINED || *earliest == ThresholdState::STARTED
                                 || *earliest == ThresholdState::LOCKED_IN)) {
                    out.active = V24State::INACTIVE;
                    out.basis = "bound";
                }
            }
        }
        return out;
    }

    DeploymentResolution apply_pin(DeploymentResolution r, uint32_t height, uint32_t pin)
    {
        const V24State pinned = height >= pin ? V24State::ACTIVE : V24State::INACTIVE;
        if (r.active == V24State::UNKNOWN) {
            r.active = pinned;
            r.basis = "override";
            return r;
        }
        if (r.active != pinned) {
            if (!m_pin_conflict_logged.exchange(true))
                LOG_ERROR << "[DASH-V24] --dash-v24-activation-height=" << pin
                          << " CONTRADICTS the computed v24 state at h=" << height
                          << " (" << v24_state_name(r.active) << ", " << r.basis
                          << "): v24 state is UNKNOWN, the embedded arm fails closed";
            r.active = V24State::UNKNOWN;
            r.basis = "override-conflict";
        }
        return r;
    }

    /// A latch clears when the recomputed (unlatched) answer agrees with the
    /// chain both at the latched block and at the block just checked (the
    /// tracker caught up or rewound, e.g. after a reorg).
    void maybe_clear_latch(uint32_t height, bool chain_active_here)
    {
        uint32_t lh;
        bool lactive;
        {
            std::lock_guard<std::mutex> lk(m_latch_mutex);
            if (m_latch == V24Latch::NONE) return;
            // A CbTx version Core rejects is refuted by nothing but the block
            // leaving the chain (revalidate_latch).
            if (m_latch_invalid_version) return;
            lh = m_latch_height;
            lactive = m_latch_chain_active;
        }
        const auto then = compute(lh, DashDeployment::V24);
        const auto now  = compute(height, DashDeployment::V24);
        if (then.active == V24State::UNKNOWN || now.active == V24State::UNKNOWN) return;
        if ((then.active == V24State::ACTIVE) != lactive) return;
        if ((now.active == V24State::ACTIVE) != chain_active_here) return;
        {
            std::lock_guard<std::mutex> lk(m_latch_mutex);
            m_latch = V24Latch::NONE;
            ++m_latch_version;
        }
        LOG_WARNING << "[DASH-V24] cross-check latch CLEARED at h=" << height
                    << ": the recomputed v24 state agrees with the chain at h=" << lh
                    << " and h=" << height;
    }

    /// CheckCbTx's version rules that need no v24 state.
    bool cbtx_version_invalid(uint32_t height, uint16_t v) const
    {
        if (v == 0 || v > 4) return true;
        if (m_params.v20_height == 0) return false;
        const bool v20 = height >= m_params.v20_height;
        return v20 ? v < 3 : v >= 3;
    }

public:
    /// Clear the latch when the block that set it is no longer on our best
    /// chain (reorged out, orphaned): our chain view holds a different block
    /// at that height. While that block is on the best chain (or the view
    /// cannot tell: no header there yet, a record without a hash) the latch
    /// stays. Called on every cross-check and by the node after it restores
    /// a persisted latch.
    void revalidate_latch()
    {
        if (m_closed.load()) return;
        uint32_t lh;
        uint256 lhash;
        {
            std::lock_guard<std::mutex> lk(m_latch_mutex);
            if (m_latch == V24Latch::NONE || m_latch_hash.IsNull()) return;
            lh = m_latch_height;
            lhash = m_latch_hash;
        }
        const auto b = m_chain(lh);
        if (!b || b->hash == lhash) return;
        {
            std::lock_guard<std::mutex> lk(m_latch_mutex);
            if (m_latch == V24Latch::NONE || m_latch_hash != lhash) return;
            m_latch = V24Latch::NONE;
            m_latch_hash.SetNull();
            m_latch_invalid_version = false;
            ++m_latch_version;
        }
        LOG_WARNING << "[DASH-V24] cross-check latch CLEARED: the block that set it (h=" << lh << " "
                    << lhash.GetHex().substr(0, 16) << ") is no longer on our best chain (now "
                    << b->hash.GetHex().substr(0, 16) << ")";
    }

    V24State v24_state(uint32_t height) { return resolve(height, DashDeployment::V24).active; }
    bool v24_active(uint32_t height) { return v24_state(height) == V24State::ACTIVE; }

    /// ComputeBlockVersion for the block at `height`: the top bits plus the
    /// bit of every deployment that is STARTED or LOCKED_IN for it (both have
    /// gbt_force, so Core's GBT keeps them). A deployment whose state is not
    /// known exactly contributes no bit: signalling is not consensus, and an
    /// unproven signal is simply omitted (design §3.1 item 7). The state is
    /// exact before the tip's own body is scanned once the signal is known
    /// (header note, item 2), so the header tip-change callback signals while
    /// STARTED / LOCKED_IN (VERIFY-H0-S0-S1 SF1).
    uint32_t block_version(uint32_t height)
    {
        uint32_t v = static_cast<uint32_t>(kVersionBitsTopBits);
        if (m_closed.load() || latch() != V24Latch::NONE) return v;   // nothing known exactly
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
        if (m_closed.load() || (dep == DashDeployment::V24 && latch() != V24Latch::NONE)) return std::nullopt;
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
            const auto sh = decided_signal_height(dep, prev);
            if (!sh) return std::nullopt;
            auto since = m_exact[static_cast<int>(dep)].state_since_height(prev, *sh);
            if (since) return static_cast<uint32_t>(*since);
        }
        return std::nullopt;
    }

    /// Signalling statistics of the period containing `height` (exact only).
    /// Core: GetStateStatisticsFor(pindex) runs the machine on the end of the
    /// previous period, so the signal height is the one as of that block.
    std::optional<VbStats> statistics(uint32_t height, DashDeployment dep)
    {
        if (m_closed.load()) return std::nullopt;
        const int64_t P = vb_period(m_params, m_params.dep(dep));
        const int64_t h = static_cast<int64_t>(height);
        const int64_t end_prev = h - ((h + 1) % P);
        const auto sh = decided_signal_height(dep, end_prev);
        if (!sh) return std::nullopt;
        return m_exact[static_cast<int>(dep)].statistics(h, *sh);
    }

private:
    /// SignalHeight(prev) when the scanned bodies decide it (see the header
    /// note, item 2), nullopt otherwise.
    std::optional<int64_t> decided_signal_height(DashDeployment dep, int64_t prev_height) const
    {
        const auto& d = m_params.dep(dep);
        if (!d.useEHF) return 0;
        // GetSignalsStage is empty before V20.
        if (prev_height + 1 < static_cast<int64_t>(m_params.v20_height)) return kNoSignalHeight;
        if (!m_ehf) return std::nullopt;
        const uint8_t bit = static_cast<uint8_t>(d.bit);
        const int64_t c = m_ehf->verified_coverage();
        if (prev_height <= c) return m_ehf->signal_height(bit, prev_height);
        // Bodies (c, prev] are not scanned (yet).
        const int64_t s = m_ehf->signal_height(bit, c);
        if (s != kNoSignalHeight) return s;   // final: a later signal cannot be lower
        const int64_t P = vb_period(m_params, d);
        const int64_t pe = prev_height - ((prev_height + 1) % P);
        if (pe <= c) return kNoSignalHeight;   // no period end in (c, prev] can read S
        return std::nullopt;
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

        if (const auto sh = decided_signal_height(dep, prev)) {
            const auto s = m_exact[idx].state_for(prev, *sh);
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
    std::atomic<bool> m_pin_conflict_logged{false};
    std::atomic<bool> m_closed{false};
    // Pin and cross-check latch (m_latch_mutex).
    mutable std::mutex m_latch_mutex;
    std::optional<uint32_t> m_pin;
    bool     m_pin_refuted{false};
    V24Latch m_latch{V24Latch::NONE};
    uint32_t m_latch_height{0};
    uint256  m_latch_hash;                 ///< the block that set the latch (null: unknown)
    bool     m_latch_chain_active{false};
    bool     m_latch_invalid_version{false};   ///< its CbTx version is one Core rejects
    uint64_t m_contradictions{0};
    uint64_t m_latch_version{0};
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

// v24_earliest_unmeasured_activation: dash_deployments.hpp.

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
