#pragma once

#include "share_types.hpp"
#include <core/log.hpp>
#include <nlohmann/json.hpp>
#include <deque>
#include <mutex>
#include <algorithm>
#include <ctime>

namespace c2pool {

/**
 * @brief Tracker for mining shares from physical miners
 * 
 * Handles VARDIFF-style difficulty adjustment and statistics
 * for shares submitted via Stratum protocol from mining hardware.
 */
class MiningShareTracker {
private:
    struct MiningShareSubmission {
        uint64_t timestamp;
        double difficulty;
        bool accepted;
        std::string miner_address;
        std::string session_id;
    };
    
    std::deque<MiningShareSubmission> recent_submissions_;
    mutable std::mutex submissions_mutex_;
    
    // Difficulty adjustment parameters
    double current_difficulty_ = 1.0;
    double target_time_per_share_ = 30.0; // Target 30 seconds per share
    uint64_t difficulty_adjustment_interval_ = 300; // 5 minutes
    uint64_t last_difficulty_adjustment_ = 0;
    
    // Difficulty bounds
    double min_difficulty_ = 0.001;
    double max_difficulty_ = 1000000.0;
    
    // Statistics
    uint64_t total_mining_shares_submitted_ = 0;
    uint64_t total_mining_shares_accepted_ = 0;
    double total_work_done_ = 0.0;
    
public:
    /**
     * @brief Record a new mining share submission
     */
    void record_mining_share(const MiningShare& share) {
        record_submission(share.get_difficulty_value(), share.m_accepted, 
                         share.m_miner_address, share.m_miner_session_id);
    }
    
    /**
     * @brief Record a mining share submission with parameters
     */
    void record_submission(double difficulty, bool accepted, 
                          const std::string& miner_address = "", 
                          const std::string& session_id = "") {
        std::lock_guard<std::mutex> lock(submissions_mutex_);
        
        uint64_t now = static_cast<uint64_t>(std::time(nullptr));
        recent_submissions_.push_back({now, difficulty, accepted, miner_address, session_id});
        
        // Keep only submissions from last hour
        while (!recent_submissions_.empty() && 
               recent_submissions_.front().timestamp < now - 3600) {
            recent_submissions_.pop_front();
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
        
        LOG_DEBUG_OTHER << "Recorded mining share: difficulty=" << difficulty 
                       << ", accepted=" << accepted << ", miner=" << miner_address;
    }
    
    /**
     * @brief Get current difficulty for miners
     */
    double get_current_difficulty() const {
        std::lock_guard<std::mutex> lock(submissions_mutex_);
        return current_difficulty_;
    }
    
    /**
     * @brief Calculate current hashrate from recent submissions
     */
    double get_current_hashrate() const {
        std::lock_guard<std::mutex> lock(submissions_mutex_);
        
        uint64_t now = static_cast<uint64_t>(std::time(nullptr));
        double work_done = 0.0;
        uint64_t time_window = 600; // 10 minutes
        
        for (const auto& submission : recent_submissions_) {
            if (submission.accepted && submission.timestamp > now - time_window) {
                work_done += submission.difficulty;
            }
        }
        
        if (time_window > 0) {
            // Hashrate = work_done / time_window * 2^32 (for difficulty 1 ≈ 4.3GH/s)
            return work_done / time_window * 4294967296.0; // 2^32
        }
        
        return 0.0;
    }
    
    /**
     * @brief Get comprehensive mining statistics
     */
    nlohmann::json get_statistics() const {
        std::lock_guard<std::mutex> lock(submissions_mutex_);
        
        uint64_t now = static_cast<uint64_t>(std::time(nullptr));
        
        // Calculate acceptance rate for last hour
        uint64_t recent_submitted = 0;
        uint64_t recent_accepted = 0;
        
        for (const auto& submission : recent_submissions_) {
            if (submission.timestamp > now - 3600) { // Last hour
                recent_submitted++;
                if (submission.accepted) recent_accepted++;
            }
        }
        
        double acceptance_rate = recent_submitted > 0 ? 
            (double)recent_accepted / recent_submitted * 100.0 : 0.0;
        
        return {
            {"type", "mining_shares"},
            {"current_difficulty", current_difficulty_},
            {"current_hashrate", get_current_hashrate()},
            {"total_mining_shares_submitted", total_mining_shares_submitted_},
            {"total_mining_shares_accepted", total_mining_shares_accepted_},
            {"total_work_done", total_work_done_},
            {"acceptance_rate_1h", acceptance_rate},
            {"recent_submissions_count", recent_submissions_.size()},
            {"target_time_per_share", target_time_per_share_},
            {"difficulty_bounds", {
                {"min", min_difficulty_},
                {"max", max_difficulty_}
            }}
        };
    }
    
    /**
     * @brief Get active miner addresses from recent submissions
     */
    std::vector<std::string> get_active_miners() const {
        std::lock_guard<std::mutex> lock(submissions_mutex_);
        
        uint64_t now = static_cast<uint64_t>(std::time(nullptr));
        std::set<std::string> active_miners;
        
        for (const auto& submission : recent_submissions_) {
            if (submission.timestamp > now - 600 && !submission.miner_address.empty()) { // Last 10 minutes
                active_miners.insert(submission.miner_address);
            }
        }
        
        return std::vector<std::string>(active_miners.begin(), active_miners.end());
    }
    
    /**
     * @brief Set difficulty adjustment parameters
     */
    void set_difficulty_bounds(double min_difficulty, double max_difficulty) {
        std::lock_guard<std::mutex> lock(submissions_mutex_);
        min_difficulty_ = min_difficulty;
        max_difficulty_ = max_difficulty;
        
        LOG_INFO << "Mining share difficulty bounds updated: min=" << min_difficulty 
                 << ", max=" << max_difficulty;
    }
    
    /**
     * @brief Set target time per share for VARDIFF
     */
    void set_target_time_per_share(double target_seconds) {
        std::lock_guard<std::mutex> lock(submissions_mutex_);
        target_time_per_share_ = target_seconds;
        
        LOG_INFO << "Mining share target time updated: " << target_seconds << " seconds";
    }
    
private:
    void adjust_difficulty() {
        if (recent_submissions_.size() < 3) {
            return; // Need minimum submissions for adjustment
        }
        
        uint64_t now = static_cast<uint64_t>(std::time(nullptr));
        
        // Calculate average time between accepted shares in last 5 minutes
        std::vector<uint64_t> accepted_times;
        for (const auto& submission : recent_submissions_) {
            if (submission.accepted && submission.timestamp > now - 300) { // Last 5 minutes
                accepted_times.push_back(submission.timestamp);
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
        double adjustment_factor = target_time_per_share_ / avg_time_per_share;
        
        // Limit adjustment to prevent oscillation
        adjustment_factor = std::max(0.5, std::min(2.0, adjustment_factor));
        
        double new_difficulty = current_difficulty_ * adjustment_factor;
        
        // Apply bounds
        new_difficulty = std::max(min_difficulty_, std::min(max_difficulty_, new_difficulty));
        
        if (std::abs(new_difficulty - current_difficulty_) / current_difficulty_ > 0.1) { // >10% change
            LOG_INFO << "Mining difficulty adjustment: " << current_difficulty_ << " -> " << new_difficulty
                     << " (avg time: " << avg_time_per_share << "s, target: " << target_time_per_share_ << "s)"
                     << " (factor: " << adjustment_factor << ")";
            current_difficulty_ = new_difficulty;
        }
    }
};

} // namespace c2pool
