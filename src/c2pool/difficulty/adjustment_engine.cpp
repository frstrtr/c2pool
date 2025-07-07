#include "adjustment_engine.hpp"
#include <algorithm>
#include <ctime>

// Forward declaration for C2PoolShare
namespace c2pool {
    struct C2PoolShare {
        uint256 m_hash;
        uint256 m_difficulty;
        uint64_t m_submit_time;
        // Other fields would be defined elsewhere
    };
}

namespace c2pool {
namespace difficulty {

void DifficultyAdjustmentEngine::process_new_p2p_share(const c2pool::C2PoolShare& share) {
    mining_shares_since_last_adjustment_++;
    
    uint64_t now = static_cast<uint64_t>(std::time(nullptr));
    
    // Update network difficulty if needed (every 10 minutes)
    if (now - last_network_update_ > 600) {
        update_network_difficulty();
        last_network_update_ = now;
    }
    
    // Check if we should adjust pool difficulty
    if (mining_shares_since_last_adjustment_ >= target_mining_shares_per_adjustment_ ||
        (now - last_adjustment_time_) > 300) { // Also adjust every 5 minutes
        
        adjust_pool_difficulty();
        last_adjustment_time_ = now;
        mining_shares_since_last_adjustment_ = 0;
    }
}

double DifficultyAdjustmentEngine::calculate_new_difficulty(uint64_t current_difficulty, double hashrate, uint64_t timestamp) {
    // Simple difficulty calculation based on hashrate
    if (hashrate <= 0) {
        return static_cast<double>(current_difficulty);
    }
    
    // Target: adjust difficulty to maintain target block time
    double time_factor = target_block_time_ / 30.0; // Assuming 30s ideal share time
    double new_difficulty = hashrate * time_factor / 1000000.0; // Scale appropriately
    
    // Bounds checking
    double min_diff = network_difficulty_ / 10000.0;
    double max_diff = network_difficulty_ / 10.0;
    
    return std::max(0.001, std::min(max_diff, std::max(min_diff, new_difficulty)));
}

void DifficultyAdjustmentEngine::apply_difficulty_adjustment(double new_difficulty) {
    if (new_difficulty > 0 && new_difficulty != current_pool_difficulty_) {
        LOG_INFO << "Applying difficulty adjustment: " << current_pool_difficulty_ 
                 << " -> " << new_difficulty;
        current_pool_difficulty_ = new_difficulty;
    }
}

double DifficultyAdjustmentEngine::get_current_pool_difficulty() const {
    return current_pool_difficulty_;
}

uint256 DifficultyAdjustmentEngine::get_pool_target() const {
    // Convert difficulty to target
    uint256 max_target;
    max_target.SetHex("00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
    
    if (current_pool_difficulty_ <= 0) {
        return max_target;
    }
    
    return max_target / static_cast<uint64_t>(current_pool_difficulty_);
}

nlohmann::json DifficultyAdjustmentEngine::get_difficulty_stats() const {
    return {
        {"pool_difficulty", current_pool_difficulty_},
        {"network_difficulty", network_difficulty_},
        {"shares_since_adjustment", mining_shares_since_last_adjustment_},
        {"target_shares_per_adjustment", target_mining_shares_per_adjustment_},
        {"pool_target", get_pool_target().ToString()},
        {"network_target", network_target_.ToString()},
        {"target_block_time", target_block_time_},
        {"last_adjustment_time", last_adjustment_time_}
    };
}

void DifficultyAdjustmentEngine::set_adjustment_parameters(uint64_t target_shares, double target_time) {
    target_mining_shares_per_adjustment_ = target_shares;
    target_block_time_ = target_time;
    LOG_INFO << "Difficulty adjustment parameters updated: " 
             << target_shares << " shares, " << target_time << "s target time";
}

void DifficultyAdjustmentEngine::force_network_update() {
    update_network_difficulty();
    last_network_update_ = static_cast<uint64_t>(std::time(nullptr));
}

void DifficultyAdjustmentEngine::update_network_difficulty() {
    // In a real implementation, this would query the network for current difficulty
    // For now, we'll simulate it
    try {
        // Query network via RPC (placeholder)
        network_difficulty_ = 1000.0; // Placeholder network difficulty
        
        // Convert to target
        uint256 max_target;
        max_target.SetHex("00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        network_target_ = max_target / static_cast<uint64_t>(network_difficulty_);
        
        LOG_INFO << "Network difficulty updated: " << network_difficulty_
                 << " (target: " << network_target_.ToString().substr(0, 16) << "...)";
        
    } catch (const std::exception& e) {
        LOG_WARNING << "Failed to update network difficulty: " << e.what();
    }
}

void DifficultyAdjustmentEngine::adjust_pool_difficulty() {
    if (mining_shares_since_last_adjustment_ == 0) return;
    
    uint64_t now = static_cast<uint64_t>(std::time(nullptr));
    uint64_t time_elapsed = now - last_adjustment_time_;
    
    if (time_elapsed == 0) time_elapsed = 1; // Prevent division by zero
    
    // Calculate actual vs target rate
    double actual_rate = (double)mining_shares_since_last_adjustment_ / time_elapsed;
    double target_rate = target_mining_shares_per_adjustment_ / target_block_time_;
    
    if (actual_rate > 0) {
        double adjustment_factor = target_rate / actual_rate;
        
        // Limit adjustment to prevent oscillation
        adjustment_factor = std::max(0.7, std::min(1.5, adjustment_factor));
        
        double new_difficulty = current_pool_difficulty_ * adjustment_factor;
        
        // Ensure difficulty stays reasonable relative to network
        double min_diff = network_difficulty_ / 10000.0; // At least 1/10000 of network
        double max_diff = network_difficulty_ / 10.0;    // At most 1/10 of network
        
        new_difficulty = std::max(0.001, std::min(max_diff, std::max(min_diff, new_difficulty)));
        
        if (std::abs(new_difficulty - current_pool_difficulty_) / current_pool_difficulty_ > 0.05) {
            LOG_INFO << "Pool difficulty adjustment: " << current_pool_difficulty_ 
                     << " -> " << new_difficulty
                     << " (rate: " << actual_rate << " shares/s, target: " << target_rate << " shares/s)"
                     << " (factor: " << adjustment_factor << ")";
            
            current_pool_difficulty_ = new_difficulty;
        }
    }
}

} // namespace difficulty
} // namespace c2pool
