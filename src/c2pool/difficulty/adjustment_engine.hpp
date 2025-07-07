#pragma once

#include <core/uint256.hpp>
#include <nlohmann/json.hpp>
#include <core/log.hpp>

// Forward declaration
namespace c2pool {
    struct C2PoolShare;
}

namespace c2pool {
namespace difficulty {

/**
 * @brief Automatic difficulty adjustment engine for C2Pool
 * 
 * Manages pool-wide difficulty adjustment based on share submission rates
 * and network conditions to maintain optimal mining performance.
 */
class DifficultyAdjustmentEngine {
private:
    double current_pool_difficulty_ = 1.0;
    uint64_t mining_shares_since_last_adjustment_ = 0;
    uint64_t target_mining_shares_per_adjustment_ = 100;
    double target_block_time_ = 150.0; // 2.5 minutes for Litecoin
    uint64_t last_adjustment_time_ = 0;
    
    // Network statistics
    uint256 network_target_;
    double network_difficulty_ = 1.0;
    uint64_t last_network_update_ = 0;
    
public:
    /**
     * @brief Process a new p2p_share for difficulty adjustment
     * @param share The C2Pool p2p_share to process
     */
    void process_new_p2p_share(const c2pool::C2PoolShare& share);
    
    /**
     * @brief Calculate new difficulty based on hashrate and timing
     * @param current_difficulty Current difficulty value
     * @param hashrate Current hashrate estimate
     * @param timestamp Current timestamp
     * @return New calculated difficulty
     */
    double calculate_new_difficulty(uint64_t current_difficulty, double hashrate, uint64_t timestamp);
    
    /**
     * @brief Apply a difficulty adjustment
     * @param new_difficulty The new difficulty to apply
     */
    void apply_difficulty_adjustment(double new_difficulty);
    
    /**
     * @brief Get current pool difficulty
     * @return Current pool difficulty value
     */
    double get_current_pool_difficulty() const;
    
    /**
     * @brief Get pool target based on current difficulty
     * @return Target as uint256
     */
    uint256 get_pool_target() const;
    
    /**
     * @brief Get comprehensive difficulty statistics
     * @return JSON object with difficulty stats
     */
    nlohmann::json get_difficulty_stats() const;
    
    /**
     * @brief Set target parameters for difficulty adjustment
     * @param target_mining_shares Number of mining_shares per adjustment period
     * @param target_time Target time per block/adjustment
     */
    void set_adjustment_parameters(uint64_t target_mining_shares, double target_time);
    
    /**
     * @brief Force a difficulty update from network
     */
    void force_network_update();
    
private:
    /**
     * @brief Update network difficulty from external source
     */
    void update_network_difficulty();
    
    /**
     * @brief Adjust pool difficulty based on recent performance
     */
    void adjust_pool_difficulty();
    
    // Backward compatibility method - delegate to new p2p_share method
    void process_new_share(const c2pool::C2PoolShare& share) {
        process_new_p2p_share(share);
    }
};

} // namespace difficulty
} // namespace c2pool
