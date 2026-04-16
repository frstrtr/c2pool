#pragma once

// Phase 1c: Whale departure recovery — non-consensus local heuristic.
//
// When a large miner (whale) suddenly leaves the P2Pool network, share
// difficulty remains calibrated for the whale's hashrate, causing remaining
// miners to produce shares very slowly (~2 min/share instead of 15s).
//
// This detector tracks pool hashrate in a 30-minute rolling window and
// triggers when the current hashrate drops below 50% of the average.
// When active, desired_share_target should be overridden to 2^256-1
// (clamped to pre_target3 — the easiest consensus-allowed difficulty).
//
// This is non-consensus: only affects what OUR node mines.
// Structured log lines: [WHALE-DEPARTURE] and [WHALE-RECOVERY].
//
// Port of p2pool-v36 work.py Phase 1c + 1c.1 (commits 77d3c7d0 + 546c5382).

#include "config_pool.hpp"
#include "share_tracker.hpp"

#include <core/log.hpp>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <string>
#include <vector>

namespace ltc
{

// Forward: fmt_hashrate is defined in pool_monitor.hpp.
// Re-declare if used standalone; the linker will pick either.
inline std::string whale_fmt_hr(double n)
{
    static const char* suffixes[] = {"", "k", "M", "G", "T", "P"};
    for (const char* s : suffixes)
    {
        if (std::abs(n) < 1000.0)
        {
            std::ostringstream os;
            os.precision(1);
            os << std::fixed << n << s;
            return os.str();
        }
        n /= 1000.0;
    }
    std::ostringstream os;
    os.precision(1);
    os << std::fixed << n << "E";
    return os.str();
}

class WhaleDepartureDetector
{
public:
    WhaleDepartureDetector() = default;

    // Returns true if whale departure is currently active.
    bool is_active() const { return active_; }

    // Call periodically (every ~5-30s) with a reference to the tracker and best hash.
    // Returns true if departure recovery mode should be active.
    bool detect(ShareTracker& tracker, const uint256& best_share_hash,
                const std::string& trigger_source = "timer")
    {
        if (best_share_hash.IsNull())
            return false;

        auto [height, last] = tracker.chain.get_height_and_last(best_share_hash);
        int32_t lookbehind = std::min(height - 1,
            static_cast<int32_t>(tracker.m_params->target_lookbehind));
        if (lookbehind < 2)
            return false;

        auto now = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();

        // Share gap
        uint32_t best_ts = 0;
        tracker.chain.get_share(best_share_hash).invoke([&](auto* obj) {
            best_ts = obj->m_timestamp;
        });
        auto share_gap = (now > best_ts) ? (now - best_ts) : int64_t(0);

        // Sample pool hashrate at fixed cadence
        double att_s = last_att_s_;
        if ((now - last_sample_ts_) >= sample_interval_ || att_s <= 0)
        {
            auto aps = tracker.get_pool_attempts_per_second(best_share_hash, lookbehind);
            att_s = static_cast<double>(aps.GetLow64());
            last_att_s_ = att_s;
            last_sample_ts_ = now;
            hr_samples_.push_back({now, att_s});
        }

        if (att_s <= 0)
            return active_;

        // Trim to rolling window
        auto cutoff = now - hr_window_;
        hr_samples_.erase(
            std::remove_if(hr_samples_.begin(), hr_samples_.end(),
                [cutoff](const HrSample& s) { return s.ts < cutoff; }),
            hr_samples_.end());

        bool enough = hr_samples_.size() >= 10;
        if (!enough && !active_)
            return false;

        double sum = 0;
        for (auto& s : hr_samples_) sum += s.hr;
        double avg_hr = hr_samples_.empty() ? 0 : sum / static_cast<double>(hr_samples_.size());

        if (avg_hr <= 0 && !active_)
            return false;

        double baseline_hr = active_ ? baseline_hr_ : avg_hr;
        if (baseline_hr <= 0)
            baseline_hr = (avg_hr > 0) ? avg_hr : att_s;
        double ratio = (baseline_hr > 0) ? att_s / baseline_hr : 1.0;

        // Secondary signal: long wall-clock share drought while below baseline
        bool gap_trigger = share_gap >= static_cast<int64_t>(
            tracker.m_params->share_period * gap_trigger_periods_);

        if (active_)
        {
            // Recovery: require sustained improvement
            if (ratio >= recovery_threshold_)
            {
                active_ = false;
                baseline_hr_ = 0;
                auto duration = now - departure_ts_;
                LOG_INFO << "[WHALE-RECOVERY] OFF src=" << trigger_source
                         << " ratio=" << ratio
                         << " gap=" << share_gap << "s"
                         << " duration=" << duration << "s"
                         << " current=" << whale_fmt_hr(att_s) << "H/s"
                         << " baseline=" << whale_fmt_hr(baseline_hr) << "H/s";
            }
            else if (now - log_interval_ > 30)
            {
                log_interval_ = now;
                LOG_INFO << "[WHALE-DEPARTURE] ACTIVE src=" << trigger_source
                         << " current=" << whale_fmt_hr(att_s) << "H/s"
                         << " baseline=" << whale_fmt_hr(baseline_hr) << "H/s"
                         << " avg_30m=" << whale_fmt_hr(avg_hr) << "H/s"
                         << " ratio=" << ratio
                         << " gap=" << share_gap << "s"
                         << " recover>" << (recovery_threshold_ * 100) << "%";
            }
        }
        else
        {
            // Detection: trigger when hashrate drops below threshold
            if ((enough && ratio <= drop_threshold_) ||
                (gap_trigger && ratio <= 0.90))
            {
                active_ = true;
                departure_ts_ = now;
                baseline_hr_ = baseline_hr;
                LOG_WARNING << "[WHALE-DEPARTURE] DETECTED src=" << trigger_source
                            << " ratio=" << ratio
                            << " gap=" << share_gap << "s"
                            << " current=" << whale_fmt_hr(att_s) << "H/s"
                            << " baseline=" << whale_fmt_hr(baseline_hr) << "H/s"
                            << " avg_30m=" << whale_fmt_hr(avg_hr) << "H/s";
            }
        }

        return active_;
    }

private:
    struct HrSample { int64_t ts; double hr; };
    std::vector<HrSample> hr_samples_;

    int64_t hr_window_           = 1800;   // 30 min rolling window
    bool    active_              = false;
    int64_t departure_ts_        = 0;
    double  baseline_hr_         = 0;
    double  drop_threshold_      = 0.50;   // trigger at 50% drop
    double  recovery_threshold_  = 0.75;   // recover at 75% of baseline
    int64_t log_interval_        = 0;
    int64_t last_sample_ts_      = 0;
    int64_t sample_interval_     = 5;      // seconds between samples
    double  last_att_s_          = 0;
    uint32_t gap_trigger_periods_ = 8;     // share gap trigger
};

} // namespace ltc
