#include "tracker.hpp"
#include <algorithm>
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
    }
    
    // Check if we should adjust difficulty
    if (now - last_difficulty_adjustment_ > difficulty_adjustment_interval_) {
        adjust_difficulty();
        last_difficulty_adjustment_ = now;
    }
}

void HashrateTracker::record_mining_share(const uint256& hash, uint64_t difficulty, uint64_t timestamp) {
    record_mining_share_submission(static_cast<double>(difficulty), true);
}

double HashrateTracker::get_current_difficulty() const {
    std::lock_guard<std::mutex> lock(shares_mutex_);
    return current_difficulty_;
}

double HashrateTracker::get_current_hashrate() const {
    std::lock_guard<std::mutex> lock(shares_mutex_);
    
    uint64_t now = static_cast<uint64_t>(std::time(nullptr));
    double work_done = 0.0;
    uint64_t time_window = 600; // 10 minutes
    
    for (const auto& share : recent_mining_shares_) {
        if (share.accepted && share.timestamp > now - time_window) {
            work_done += share.difficulty;
        }
    }
    
    if (time_window > 0) {
        // Hashrate = work_done / time_window * 2^32 (for difficulty 1 = ~4.3GH/s)
        return work_done / time_window * 4294967296.0; // 2^32
    }
    
    return 0.0;
}

nlohmann::json HashrateTracker::get_statistics() const {
    std::lock_guard<std::mutex> lock(shares_mutex_);
    
    uint64_t now = static_cast<uint64_t>(std::time(nullptr));
    
    // Calculate acceptance rate for last hour
    uint64_t recent_submitted = 0;
    uint64_t recent_accepted = 0;
    
    for (const auto& share : recent_mining_shares_) {
        if (share.timestamp > now - 3600) { // Last hour
            recent_submitted++;
            if (share.accepted) recent_accepted++;
        }
    }
    
    double acceptance_rate = recent_submitted > 0 ? 
        (double)recent_accepted / recent_submitted * 100.0 : 0.0;
    
    return {
        {"current_difficulty", current_difficulty_},
        {"current_hashrate", get_current_hashrate()},
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
}

void HashrateTracker::set_target_time_per_mining_share(double target_seconds) {
    std::lock_guard<std::mutex> lock(shares_mutex_);
    target_time_per_mining_share_ = target_seconds;
}

void HashrateTracker::adjust_difficulty() {
    if (recent_mining_shares_.size() < 3) {
        return; // Need minimum shares for adjustment
    }
    
    uint64_t now = static_cast<uint64_t>(std::time(nullptr));
    
    // Calculate average time between accepted shares in last 5 minutes
    std::vector<uint64_t> accepted_times;
    for (const auto& share : recent_mining_shares_) {
        if (share.accepted && share.timestamp > now - 300) { // Last 5 minutes
            accepted_times.push_back(share.timestamp);
        }
    }
    
    if (accepted_times.size() < 2) {
        return; // Need at least 2 accepted shares
    }
    
    std::sort(accepted_times.begin(), accepted_times.end());
    
    // Calculate average time between shares
    double total_time = accepted_times.back() - accepted_times.front();
    double avg_time_per_share = total_time / (accepted_times.size() - 1);
    
    // Calculate adjustment factor
    double adjustment_factor = target_time_per_mining_share_ / avg_time_per_share;
    
    // Limit adjustment to prevent oscillation
    adjustment_factor = std::max(0.5, std::min(2.0, adjustment_factor));
    
    double new_difficulty = current_difficulty_ * adjustment_factor;
    
    // Apply bounds
    new_difficulty = std::max(min_difficulty_, std::min(max_difficulty_, new_difficulty));
    
    if (std::abs(new_difficulty - current_difficulty_) / current_difficulty_ > 0.1) { // >10% change
        LOG_INFO << "Difficulty adjustment: " << current_difficulty_ << " -> " << new_difficulty
                 << " (avg time: " << avg_time_per_share << "s, target: " << target_time_per_mining_share_ << "s)"
                 << " (factor: " << adjustment_factor << ")";
        current_difficulty_ = new_difficulty;
    }
}

} // namespace hashrate
} // namespace c2pool
