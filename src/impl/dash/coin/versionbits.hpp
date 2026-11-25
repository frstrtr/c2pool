// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

/// Versionbits state machine with EHF start heights, ported from Dash Core
/// v24.0.0 src/versionbits.cpp:
///   AbstractThresholdConditionChecker::GetStateFor          -> state_for
///   calculateStartHeight                                    -> (inline)
///   AbstractThresholdConditionChecker::GetStateSinceHeightFor -> state_since_height
///   AbstractThresholdConditionChecker::GetStateStatisticsFor -> statistics
///   VersionBitsConditionChecker::{Period, Threshold, Condition, SignalHeight}
///   VersionBitsCache::ComputeBlockVersion                   -> compute_block_version
///
/// Differences in shape, not in result:
///   * The chain is addressed by height along the active chain. `prev_height`
///     plays Core's pindexPrev; -1 is the null pointer (the genesis parent).
///     A VbChainFn supplies {nVersion, nTime, hash} per height; the median
///     time past is computed here exactly as CBlockIndex::GetMedianTimePast
///     (median of up to 11 timestamps ending at the block).
///   * SignalHeight (the EHF stage, ehf_tracker.hpp) is passed in. Core reads
///     it once per query from GetSignalsStage(pindexPrev) and so do we.
///   * Every result is optional: a header the chain view cannot supply makes
///     the answer unknown (nullopt) instead of a guess.
///   * The per-period-end cache is validated against the block hash, so a
///     reorg can never serve a stale state. It is keyed by the period end and
///     the EFFECTIVE signal height for it: the state at period end E depends
///     on SignalHeight S only through the comparisons E' >= S for period ends
///     E' <= E, so every S above E is the same as "no signal" (INT_MAX). That
///     is also what Core's per-ancestor SignalHeight gives, and it keeps a
///     query below the signal (which sees no signal) from evicting an entry a
///     later query walks back into.

#include <impl/dash/coin/dash_deployments.hpp>

#include <core/uint256.hpp>

#include <algorithm>
#include <cstdint>
#include <functional>
#include <limits>
#include <map>
#include <mutex>
#include <optional>
#include <utility>
#include <vector>

namespace dash {
namespace coin {

struct VbBlockInfo
{
    int32_t  nVersion{0};
    uint32_t nTime{0};
    uint256  hash;
};

/// Header of the active-chain block at `height`, or nullopt when unknown.
using VbChainFn = std::function<std::optional<VbBlockInfo>(uint32_t height)>;

/// "No signal yet": Core's SignalHeight returns INT_MAX.
inline constexpr int64_t kNoSignalHeight = std::numeric_limits<int>::max();

/// CBlockIndex::GetMedianTimePast for the block at `height` (nMedianTimeSpan =
/// 11). Below height 10 the span is shorter, as in Core near genesis.
inline std::optional<int64_t> vb_median_time_past(const VbChainFn& chain, int64_t height)
{
    if (height < 0) return std::nullopt;
    int64_t times[11];
    int n = 0;
    for (int64_t h = height; h >= 0 && n < 11; --h) {
        auto b = chain(static_cast<uint32_t>(h));
        if (!b) return std::nullopt;
        times[n++] = b->nTime;
    }
    std::sort(times, times + n);
    return times[n / 2];
}

/// BIP9Stats.
struct VbStats
{
    int  period{0};
    int  threshold{0};
    int  elapsed{0};
    int  count{0};
    bool possible{false};
};

/// One deployment's checker over one chain view.
class VersionBitsChecker
{
public:
    VersionBitsChecker(const DashDeploymentParams& params, DashDeployment dep, VbChainFn chain)
        : m_params(params), m_dep(params.dep(dep)), m_chain(std::move(chain))
    {}

    const Bip9Deployment& deployment() const { return m_dep; }
    int64_t period() const { return vb_period(m_params, m_dep); }
    int64_t threshold(int64_t attempt) const { return vb_threshold(m_params, m_dep, attempt); }

    /// GetStateFor(pindexPrev): the state of the block at prev_height + 1.
    /// `signal_height` = SignalHeight(pindexPrev): the mined height of the
    /// unexpired EHF signal for this bit, kNoSignalHeight if none (0 when the
    /// deployment does not use EHF).
    std::optional<ThresholdState> state_for(int64_t prev_height, int64_t signal_height)
    {
        std::lock_guard<std::mutex> lk(m_mutex);
        return state_for_locked(prev_height, signal_height);
    }

    /// GetStateSinceHeightFor(pindexPrev): the first height of the run of
    /// periods that share the state of the block at prev_height + 1.
    std::optional<int64_t> state_since_height(int64_t prev_height, int64_t signal_height)
    {
        std::lock_guard<std::mutex> lk(m_mutex);
        return since_locked(prev_height, signal_height);
    }

    /// GetStateStatisticsFor(pindex): signalling statistics of the period
    /// that contains `height` (pindex), as Core reports for
    /// getdeploymentinfo / getblockchaininfo. `signal_height` is the signal
    /// height as of the period's parent (end_prev below); any value as of a
    /// later block in the period gives the same answer (see the cache note).
    std::optional<VbStats> statistics(int64_t height, int64_t signal_height)
    {
        std::lock_guard<std::mutex> lk(m_mutex);
        VbStats st;
        const int64_t P = period();
        st.period = static_cast<int>(P);
        st.threshold = static_cast<int>(threshold(0));
        if (height < 0) return st;
        int64_t blocks_in_period = 1 + (height % P);
        const int64_t end_prev = height - ((height + 1) % P);
        int64_t attempt = 0;
        const auto state = state_for_locked(end_prev, signal_height);
        if (!state) return std::nullopt;
        if (*state == ThresholdState::STARTED) {
            const auto since = since_locked(end_prev, signal_height);
            if (!since) return std::nullopt;
            attempt = (end_prev + 1 - *since) / P;
        }
        st.threshold = static_cast<int>(threshold(attempt));
        int elapsed = 0, count = 0;
        int64_t cur = height;
        do {
            ++elapsed;
            --blocks_in_period;
            auto b = m_chain(static_cast<uint32_t>(cur));
            if (!b) return std::nullopt;
            if (vb_signals(b->nVersion, m_dep)) ++count;
            --cur;
        } while (blocks_in_period > 0);
        st.elapsed = elapsed;
        st.count = count;
        st.possible = (st.period - st.threshold) >= (st.elapsed - count);
        return st;
    }

    /// Drop every cached state (tests, or a deep reorg).
    void clear()
    {
        std::lock_guard<std::mutex> lk(m_mutex);
        m_cache.clear();
    }

    size_t cache_size() const
    {
        std::lock_guard<std::mutex> lk(m_mutex);
        return m_cache.size();
    }

    /// The signal height that decides the state at period end `pe`: S itself
    /// when S <= pe, otherwise "no signal" (see the cache note above).
    static int64_t effective_signal_height(int64_t pe, int64_t signal_height)
    {
        return signal_height <= pe ? signal_height : kNoSignalHeight;
    }

    /// Entries above this are dropped wholesale (signal heights that changed
    /// with reorgs leave unreachable keys behind; recomputing is cheap).
    static constexpr size_t kMaxCacheEntries = 8192;

private:
    struct CacheEntry
    {
        uint256        hash;
        ThresholdState state{ThresholdState::DEFINED};
    };
    using CacheKey = std::pair<int64_t, int64_t>;   // {period end, effective signal height}

    std::optional<int64_t> since_locked(int64_t prev_height, int64_t signal_height)
    {
        if (m_dep.nStartTime == Bip9Deployment::ALWAYS_ACTIVE
            || m_dep.nStartTime == Bip9Deployment::NEVER_ACTIVE)
            return 0;
        const auto initial = state_for_locked(prev_height, signal_height);
        if (!initial) return std::nullopt;
        if (*initial == ThresholdState::DEFINED) return 0;
        const int64_t P = period();
        if (prev_height < 0) return std::nullopt;
        int64_t prev = prev_height - ((prev_height + 1) % P);
        int64_t parent = prev - P;
        while (parent >= 0) {
            const auto s = state_for_locked(parent, signal_height);
            if (!s) return std::nullopt;
            if (*s != *initial) break;
            prev = parent;
            parent = prev - P;
        }
        return prev + 1;
    }

    /// Cached state of the period end at `h`, if it is still valid.
    std::optional<ThresholdState> cached(int64_t h, int64_t signal_height)
    {
        auto it = m_cache.find(CacheKey{h, effective_signal_height(h, signal_height)});
        if (it == m_cache.end()) return std::nullopt;
        if (h >= 0) {
            auto b = m_chain(static_cast<uint32_t>(h));
            if (!b || b->hash != it->second.hash) return std::nullopt;
        }
        return it->second.state;
    }

    bool put(int64_t h, int64_t signal_height, ThresholdState s)
    {
        CacheEntry e;
        e.state = s;
        if (h >= 0) {
            auto b = m_chain(static_cast<uint32_t>(h));
            if (!b) return false;
            e.hash = b->hash;
        }
        m_cache[CacheKey{h, effective_signal_height(h, signal_height)}] = e;
        return true;
    }

    std::optional<ThresholdState> state_for_locked(int64_t prev_height, int64_t signal_height)
    {
        if (m_cache.size() > kMaxCacheEntries) m_cache.clear();
        auto r = state_for_once(prev_height, signal_height);
        if (!r.missing_start) return r.state;
        // calculateStartHeight met a STARTED entry whose predecessor is not
        // cached (Core asserts this cannot happen; here an entry can be
        // evicted or replaced after a reorg). Recompute from scratch rather
        // than report an unknown state.
        m_cache.clear();
        return state_for_once(prev_height, signal_height).state;
    }

    struct Once
    {
        std::optional<ThresholdState> state;
        bool missing_start{false};
    };

    Once state_for_once(int64_t prev_height, int64_t signal_height)
    {
        const int64_t P = period();
        const int64_t start = m_dep.nStartTime;
        const int64_t timeout = m_dep.nTimeout;
        const int64_t min_activation_height = m_dep.min_activation_height;

        if (start == Bip9Deployment::ALWAYS_ACTIVE) return {ThresholdState::ACTIVE};
        if (start == Bip9Deployment::NEVER_ACTIVE) return {ThresholdState::FAILED};

        // A block's state is that of the first block of its period, computed
        // from the period end (height multiple of P, minus 1).
        int64_t prev = prev_height;
        if (prev >= 0) prev = prev - ((prev + 1) % P);

        // Walk back in steps of P to a period end whose state is known.
        std::vector<int64_t> to_compute;
        ThresholdState state = ThresholdState::DEFINED;
        for (;;) {
            if (auto c = cached(prev, signal_height)) { state = *c; break; }
            if (prev < 0) {
                // The genesis block is by definition DEFINED.
                put(prev, signal_height, ThresholdState::DEFINED);
                state = ThresholdState::DEFINED;
                break;
            }
            if (prev < m_params.min_bip9_warning_height) {
                if (!put(prev, signal_height, ThresholdState::DEFINED)) return {};
                state = ThresholdState::DEFINED;
                break;
            }
            const auto mtp = vb_median_time_past(m_chain, prev);
            if (!mtp) return {};
            if (*mtp < start || prev < signal_height) {
                if (!put(prev, signal_height, ThresholdState::DEFINED)) return {};
                state = ThresholdState::DEFINED;
                break;
            }
            to_compute.push_back(prev);
            prev -= P;
        }

        if (to_compute.empty()) return {state};

        // calculateStartHeight: walk back over cached STARTED period ends.
        int64_t nStartHeight = std::numeric_limits<int>::max();
        {
            int64_t p = prev;
            ThresholdState s = state;
            while (s == ThresholdState::STARTED) {
                nStartHeight = std::min<int64_t>(p + 1, nStartHeight);
                p -= P;
                auto c = cached(p, signal_height);
                if (!c) return {std::nullopt, true};   // Core asserts the entry exists
                s = *c;
            }
        }

        // Walk forward, computing each period end's state.
        while (!to_compute.empty()) {
            ThresholdState next = state;
            const int64_t pe = to_compute.back();
            to_compute.pop_back();
            switch (state) {
            case ThresholdState::DEFINED: {
                const auto mtp = vb_median_time_past(m_chain, pe);
                if (!mtp) return {};
                if (*mtp >= start && pe >= signal_height) {
                    next = ThresholdState::STARTED;
                    nStartHeight = pe + 1;
                }
                break;
            }
            case ThresholdState::STARTED: {
                const int64_t attempt = (pe - nStartHeight) / P;
                const int64_t thr = threshold(attempt);
                int64_t count = 0;
                int64_t cur = pe;
                for (int64_t i = 0; count + (P - i) >= thr && i < P; ++i) {
                    auto b = m_chain(static_cast<uint32_t>(cur));
                    if (!b) return {};
                    if (vb_signals(b->nVersion, m_dep)) ++count;
                    --cur;
                }
                if (count >= thr) {
                    next = ThresholdState::LOCKED_IN;
                } else {
                    const auto mtp = vb_median_time_past(m_chain, pe);
                    if (!mtp) return {};
                    if (*mtp >= timeout) next = ThresholdState::FAILED;
                }
                break;
            }
            case ThresholdState::LOCKED_IN:
                if (pe + 1 >= min_activation_height) next = ThresholdState::ACTIVE;
                break;
            case ThresholdState::FAILED:
            case ThresholdState::ACTIVE:
                break;
            }
            if (!put(pe, signal_height, next)) return {};
            state = next;
        }
        return {state};
    }

    const DashDeploymentParams& m_params;
    Bip9Deployment              m_dep;
    VbChainFn                   m_chain;
    mutable std::mutex          m_mutex;
    std::map<CacheKey, CacheEntry> m_cache;
};

} // namespace coin
} // namespace dash
