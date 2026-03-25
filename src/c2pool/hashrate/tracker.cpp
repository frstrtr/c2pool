#include "tracker.hpp"
#include <algorithm>
#include <cmath>
#include <vector>

namespace c2pool {
namespace hashrate {

void HashrateTracker::record_mining_share_submission(double difficulty, bool accepted) {
    std::lock_guard<std::mutex> lock(shares_mutex_);

    uint64_t now = static_cast<uint64_t>(std::time(nullptr));
    recent_mining_shares_.push_back({now, difficulty, accepted});

    // Keep only shares from last hour
    while (!recent_mining_shares_.empty() &&
           recent_mining_shares_.front().timestamp < now - 3600) {
        recent_mining_shares_.pop_front();
    }

    total_mining_shares_submitted_++;
    if (accepted) {
        total_mining_shares_accepted_++;
        total_work_done_ += difficulty;

        // Only accepted shares inform vardiff timing (matching p2pool).
        // Stale-job submissions arrive in bursts and would make vardiff
        // think the miner is 10-100x faster → difficulty spikes.
        auto tp = clock::now();
        recent_share_times_.push_back(tp);
    }

    adjust_difficulty();
}

void HashrateTracker::record_mining_share(const uint256& hash, uint64_t difficulty, uint64_t timestamp) {
    record_mining_share_submission(static_cast<double>(difficulty), true);
}

double HashrateTracker::get_current_difficulty() const {
    std::lock_guard<std::mutex> lock(shares_mutex_);
    return current_difficulty_;
}

bool HashrateTracker::difficulty_changed_since(double old_difficulty) const {
    std::lock_guard<std::mutex> lock(shares_mutex_);
    return current_difficulty_ != old_difficulty;
}

double HashrateTracker::get_current_hashrate() const {
    std::lock_guard<std::mutex> lock(shares_mutex_);
    return get_current_hashrate_unlocked();
}

double HashrateTracker::get_current_hashrate_unlocked() const {
    uint64_t now = static_cast<uint64_t>(std::time(nullptr));
    double work_done = 0.0;
    uint64_t time_window = 600; // 10 minutes

    for (const auto& share : recent_mining_shares_) {
        if (share.accepted && share.timestamp > now - time_window) {
            work_done += share.difficulty;
        }
    }

    if (time_window > 0) {
        return work_done / time_window * 4294967296.0; // 2^32
    }
    return 0.0;
}

nlohmann::json HashrateTracker::get_statistics() const {
    std::lock_guard<std::mutex> lock(shares_mutex_);

    uint64_t now = static_cast<uint64_t>(std::time(nullptr));
    uint64_t recent_submitted = 0;
    uint64_t recent_accepted = 0;

    for (const auto& share : recent_mining_shares_) {
        if (share.timestamp > now - 3600) {
            recent_submitted++;
            if (share.accepted) recent_accepted++;
        }
    }

    double acceptance_rate = recent_submitted > 0 ?
        (double)recent_accepted / recent_submitted * 100.0 : 0.0;

    return {
        {"current_difficulty", current_difficulty_},
        {"current_hashrate", get_current_hashrate_unlocked()},
        {"total_mining_shares_submitted", total_mining_shares_submitted_},
        {"total_mining_shares_accepted", total_mining_shares_accepted_},
        {"total_work_done", total_work_done_},
        {"acceptance_rate_1h", acceptance_rate},
        {"recent_mining_shares_count", recent_mining_shares_.size()},
        {"target_time_per_mining_share", target_time_per_mining_share_},
        {"min_difficulty", min_difficulty_},
        {"max_difficulty", max_difficulty_}
    };
}

void HashrateTracker::set_difficulty_bounds(double min_difficulty, double max_difficulty) {
    std::lock_guard<std::mutex> lock(shares_mutex_);
    min_difficulty_ = min_difficulty;
    max_difficulty_ = max_difficulty;
    // Start at min difficulty so any miner can begin submitting immediately;
    // aggressive vardiff will ramp up within seconds based on actual hashrate.
    current_difficulty_ = min_difficulty_;
}

void HashrateTracker::set_target_time_per_mining_share(double target_seconds) {
    std::lock_guard<std::mutex> lock(shares_mutex_);
    target_time_per_mining_share_ = target_seconds;
}

void HashrateTracker::enable_vardiff(bool enabled) {
    std::lock_guard<std::mutex> lock(shares_mutex_);
    vardiff_enabled_ = enabled;
}

void HashrateTracker::set_difficulty_hint(double hint) {
    std::lock_guard<std::mutex> lock(shares_mutex_);
    double clamped = std::max(min_difficulty_, std::min(max_difficulty_, hint));
    if (std::abs(clamped - current_difficulty_) > 1e-9) {
        LOG_INFO << "[Stratum] Applying difficulty hint: " << current_difficulty_ << " -> " << clamped;
        current_difficulty_ = clamped;
    }
}

// Matches p2pool's stratum vardiff algorithm (stratum.py:546-573).
// Matches p2pool's stratum vardiff algorithm (stratum.py:546-573).
// Adjusts difficulty to target ~target_time_per_mining_share_ seconds per pseudoshare.
//
// Two triggers (matching p2pool exactly):
//   1) Normal: after VARDIFF_TRIGGER shares accumulated.
//   2) Timeout: elapsed time exceeds TIMEOUT_MULT * N * target_time.
//
// No quick-ramp — it causes oscillation when natural variance produces
// 2 back-to-back shares at the correct difficulty level.
// No cooldown — p2pool doesn't use one; the window reset after each
// adjustment means VARDIFF_TRIGGER shares must accumulate again.
void HashrateTracker::adjust_difficulty() {
    if (!vardiff_enabled_)
        return;

    size_t num_shares = recent_share_times_.size();
    if (num_shares == 0)
        return;

    auto now = clock::now();

    double elapsed = std::chrono::duration<double>(now - recent_share_times_.front()).count();

    bool should_adjust = false;

    // Trigger 1 (p2pool): enough shares accumulated
    if (num_shares > VARDIFF_TRIGGER)
        should_adjust = true;

    // Trigger 2 (p2pool): time since first share > TIMEOUT_MULT * N * target_time
    if (elapsed > TIMEOUT_MULT * static_cast<double>(num_shares) * target_time_per_mining_share_)
        should_adjust = true;

    if (!should_adjust)
        return;

    // p2pool algorithm (stratum.py:572-577):
    //   old_time = self.recent_shares[0]
    //   del self.recent_shares[0]          # remove first → len becomes N-1
    //   ratio = (now - old_time) / (len(self.recent_shares) * share_rate)
    //   target *= clip(ratio, 0.1, 10.0)
    //
    // N timestamps define N-1 intervals. elapsed spans from first to last.
    // p2pool uses (N-1) in the denominator (after deleting [0]).
    // We must do the same: num_shares - 1 intervals.
    size_t intervals = num_shares - 1;  // N timestamps → N-1 intervals (matches p2pool del [0])
    double ratio = (intervals > 0) ? elapsed / (static_cast<double>(intervals) * target_time_per_mining_share_) : 1.0;

    // Avoid extreme ratios from sub-millisecond bursts
    ratio = std::max(MIN_ADJUST, std::min(MAX_ADJUST, ratio));

    double new_difficulty = current_difficulty_ / ratio;
    new_difficulty = std::max(min_difficulty_, std::min(max_difficulty_, new_difficulty));

    if (std::abs(new_difficulty - current_difficulty_) / std::max(current_difficulty_, 0.001) > 0.01) {
        LOG_INFO << "[Stratum] VARDIFF: " << current_difficulty_ << " -> " << new_difficulty
                 << " (" << num_shares << " shares in " << elapsed << "s"
                 << ", ratio=" << ratio
                 << ", target=" << target_time_per_mining_share_ << "s)";
        current_difficulty_ = new_difficulty;
    }

    // Reset window — keep only the most recent timestamp (matches p2pool)
    recent_share_times_.clear();
    recent_share_times_.push_back(now);
}

} // namespace hashrate
} // namespace c2pool
