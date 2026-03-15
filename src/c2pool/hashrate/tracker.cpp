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

        // Only accepted shares inform vardiff timing.
        // Rejected shares are stale pipeline artefacts from the miner
        // still mining at a previous (lower) difficulty and would make
        // vardiff think the miner is faster than it really is.
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

// Python-style aggressive vardiff.  Called after every share submission.
// Three triggers:
//   1) Normal: after VARDIFF_TRIGGER shares, scale by actual_rate / target_rate.
//   2) Quick-up: 2 shares in < target/3 time → ramp up immediately.
//   3) Timeout: if time since last share > 5 * target → ramp down.
//
// After each adjustment, enforce a cooldown of target_time seconds so the miner
// has time to apply the new set_difficulty before we measure again.
void HashrateTracker::adjust_difficulty() {
    if (!vardiff_enabled_)
        return;

    size_t num_shares = recent_share_times_.size();
    if (num_shares == 0)
        return;

    auto now = clock::now();

    // Cooldown: skip adjustment if we adjusted recently.
    // This prevents spiraling when a burst of queued shares arrives
    // before the miner applies the new set_difficulty.
    double since_last_adjust = std::chrono::duration<double>(now - last_adjust_time_).count();
    if (last_adjust_time_ != time_point{} && since_last_adjust < target_time_per_mining_share_)
        return;

    double elapsed = std::chrono::duration<double>(now - recent_share_times_.front()).count();
    double target_time = static_cast<double>(num_shares) * target_time_per_mining_share_;

    bool should_adjust = false;

    // Trigger 1: enough shares accumulated
    if (num_shares >= VARDIFF_TRIGGER)
        should_adjust = true;

    // Trigger 2: quick ramp-up — shares arriving much faster than target
    if (num_shares >= QUICKUP_SHARES && elapsed < target_time / QUICKUP_DIVISOR)
        should_adjust = true;

    // Trigger 3: timeout — no shares for a long time (elapsed >> target_time)
    if (num_shares >= 1 && elapsed > TIMEOUT_MULT * target_time)
        should_adjust = true;

    if (!should_adjust)
        return;

    double actual_rate = (num_shares > 0) ? elapsed / num_shares : target_time_per_mining_share_;

    // Avoid division by zero if shares arrive in <1ms
    if (actual_rate < 0.001)
        actual_rate = 0.001;

    double adjustment = actual_rate / target_time_per_mining_share_;
    adjustment = std::max(MIN_ADJUST, std::min(MAX_ADJUST, adjustment));

    double new_difficulty = current_difficulty_ / adjustment;
    new_difficulty = std::max(min_difficulty_, std::min(max_difficulty_, new_difficulty));

    if (std::abs(new_difficulty - current_difficulty_) / std::max(current_difficulty_, 0.001) > 0.05) {
        LOG_INFO << "[Stratum] VARDIFF: " << current_difficulty_ << " -> " << new_difficulty
                 << " (" << num_shares << " shares in " << elapsed << "s"
                 << ", actual_rate=" << actual_rate << "s"
                 << ", target=" << target_time_per_mining_share_ << "s)";
        current_difficulty_ = new_difficulty;
        last_adjust_time_ = now;
    }

    // Reset window — keep only the most recent timestamp
    recent_share_times_.clear();
    recent_share_times_.push_back(now);
}

} // namespace hashrate
} // namespace c2pool
