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

void HashrateTracker::set_vardiff_params(const core::CoinParams::VardiffConfig& cfg) {
    std::lock_guard<std::mutex> lock(shares_mutex_);
    target_time_per_mining_share_ = cfg.target_share_rate;
    vardiff_trigger_              = cfg.shares_trigger;
    vardiff_timeout_              = cfg.timeout_mult;
    vardiff_min_adj_              = cfg.min_adjust;
    vardiff_max_adj_              = cfg.max_adjust;
    vardiff_quickup_n_            = cfg.quickup_shares;
    vardiff_quickup_div_          = cfg.quickup_divisor;
    vardiff_full_window_          = cfg.use_full_window;
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

// Per-session pseudoshare vardiff. Behavior depends on vardiff_* instance
// fields — defaults match upstream p2pool-merged-v36 LTC (stratum.py:568-594);
// Dash overrides via set_vardiff_params to match p2pool-dash/dash/stratum.py
// which adds a quickup trigger and uses the full-N window denominator.
//
// LTC ref (2-trigger):
//   if N > 12 or elapsed > 10*N*share_rate:
//     del recent_shares[0]  →  ratio = elapsed / ((N−1) * share_rate)
//     target *= clip(ratio, 0.1, 10.0)
//
// Dash ref (3-trigger with quickup):
//   num_shares = len(recent_shares)
//   target_time = num_shares * share_rate
//   should_adjust = num_shares >= 8
//                OR (num_shares >= 1 and elapsed > 5 * target_time)
//                OR (num_shares >= 2 and elapsed < target_time / 3)
//   if should_adjust:
//     actual_rate = elapsed / num_shares
//     adjustment = clip(actual_rate / share_rate, 0.5, 2.0)
//     target *= adjustment
void HashrateTracker::adjust_difficulty() {
    if (!vardiff_enabled_)
        return;

    size_t num_shares = recent_share_times_.size();
    if (num_shares == 0)
        return;

    auto now = clock::now();

    double elapsed = std::chrono::duration<double>(now - recent_share_times_.front()).count();
    double target_time = static_cast<double>(num_shares) * target_time_per_mining_share_;

    bool should_adjust = false;

    // Trigger 1: enough shares accumulated.
    // LTC upstream uses strict >, p2pool-dash uses >=. Matching each by
    // comparing against the coin-configured value: >= for Dash (quickup
    // on), > for LTC (quickup off, trigger just reads "more than N").
    if (vardiff_quickup_n_ > 0) {
        if (num_shares >= vardiff_trigger_)
            should_adjust = true;
    } else {
        if (num_shares > vardiff_trigger_)
            should_adjust = true;
    }

    // Trigger 2: time since first share > timeout_mult * N * share_rate.
    if (elapsed > vardiff_timeout_ * target_time)
        should_adjust = true;

    // Trigger 3 (Dash quickup — disabled for LTC since vardiff_quickup_n_ == 0):
    // if enough shares AND they came in faster than target_time/divisor.
    if (vardiff_quickup_n_ > 0
        && num_shares >= vardiff_quickup_n_
        && elapsed < target_time / vardiff_quickup_div_) {
        should_adjust = true;
    }

    if (!should_adjust)
        return;

    // Denominator policy:
    //   use_full_window=true (Dash): divisor = N
    //   use_full_window=false (LTC): divisor = N−1 (matches del recent_shares[0])
    double denom_shares;
    if (vardiff_full_window_) {
        denom_shares = static_cast<double>(num_shares);
    } else {
        denom_shares = static_cast<double>(num_shares > 1 ? num_shares - 1 : 1);
    }

    double ratio = (denom_shares > 0 && target_time_per_mining_share_ > 0)
        ? elapsed / (denom_shares * target_time_per_mining_share_)
        : 1.0;

    // Clip to coin-configured bounds (LTC: 0.1/10.0; Dash: 0.5/2.0).
    ratio = std::max(vardiff_min_adj_, std::min(vardiff_max_adj_, ratio));

    // In p2pool: target *= ratio  →  in diff space: diff /= ratio.
    double new_difficulty = current_difficulty_ / ratio;
    new_difficulty = std::max(min_difficulty_, std::min(max_difficulty_, new_difficulty));

    if (std::abs(new_difficulty - current_difficulty_) / std::max(current_difficulty_, 0.001) > 0.01) {
        LOG_INFO << "[Stratum] VARDIFF: " << current_difficulty_ << " -> " << new_difficulty
                 << " (" << num_shares << " shares in " << elapsed << "s"
                 << ", ratio=" << ratio
                 << ", target=" << target_time_per_mining_share_ << "s)";
        current_difficulty_ = new_difficulty;
    }

    // Reset window — keep only the most recent timestamp (matches both refs).
    recent_share_times_.clear();
    recent_share_times_.push_back(now);
}

} // namespace hashrate
} // namespace c2pool
