#pragma once

#include <deque>
#include <mutex>
#include <ctime>
#include <nlohmann/json.hpp>
#include <core/log.hpp>
#include <core/uint256.hpp>

namespace c2pool {
namespace hashrate {

/**
 * @brief Real-time hashrate tracking and difficulty adjustment for miners
 * 
 * Provides VARDIFF-style difficulty adjustment based on share submission timing
 * and maintains statistics for mining pool management.
 */
class HashrateTracker {
private:
    struct ShareSubmission {
        uint64_t timestamp;
        double difficulty;
        bool accepted;
    };
    
    std::deque<ShareSubmission> recent_shares_;
    mutable std::mutex shares_mutex_;
    double current_difficulty_ = 1.0;
    double target_time_per_share_ = 30.0; // Target 30 seconds per share
    uint64_t difficulty_adjustment_interval_ = 300; // 5 minutes
    uint64_t last_difficulty_adjustment_ = 0;
    
    // Difficulty bounds
    double min_difficulty_ = 0.001;
    double max_difficulty_ = 1000000.0;
    
    // Statistics
    uint64_t total_shares_submitted_ = 0;
    uint64_t total_shares_accepted_ = 0;
    double total_work_done_ = 0.0;
    
public:
    /**
     * @brief Record a new share submission
     * @param difficulty The difficulty of the submitted share
     * @param accepted Whether the share was accepted
     */
    void record_share_submission(double difficulty, bool accepted);
    
    /**
     * @brief Record a share with hash and timestamp
     * @param hash The share hash (for tracking)
     * @param difficulty The share difficulty 
     * @param timestamp The submission timestamp
     */
    void record_share(const uint256& hash, uint64_t difficulty, uint64_t timestamp);
    
    /**
     * @brief Get current difficulty for this tracker
     * @return Current difficulty value
     */
    double get_current_difficulty() const;
    
    /**
     * @brief Calculate current hashrate based on recent shares
     * @return Estimated hashrate in H/s
     */
    double get_current_hashrate() const;
    
    /**
     * @brief Get comprehensive statistics as JSON
     * @return JSON object with all statistics
     */
    nlohmann::json get_statistics() const;
    
    /**
     * @brief Set difficulty bounds
     * @param min_difficulty Minimum allowed difficulty
     * @param max_difficulty Maximum allowed difficulty
     */
    void set_difficulty_bounds(double min_difficulty, double max_difficulty);
    
    /**
     * @brief Set target time per share for difficulty adjustment
     * @param target_seconds Target time between shares in seconds
     */
    void set_target_time_per_share(double target_seconds);
    
private:
    /**
     * @brief Adjust difficulty based on recent share timing
     */
    void adjust_difficulty();
};

} // namespace hashrate
} // namespace c2pool
