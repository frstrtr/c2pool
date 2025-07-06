#pragma once

#include <memory>
#include <sharechain/legacy/base_share_tracker.hpp>
#include <c2pool/hashrate/tracker.hpp>
#include <c2pool/difficulty/adjustment_engine.hpp>
#include <core/uint256.hpp>

// Forward declaration
namespace c2pool {
    struct C2PoolShare;
}

namespace c2pool {
namespace bridge {

/**
 * @brief Bridge between legacy share tracking and new difficulty adjustment systems
 * 
 * Provides compatibility with existing share tracking infrastructure while
 * integrating new hashrate tracking and difficulty adjustment features.
 */
class LegacyShareTrackerBridge {
private:
    std::unique_ptr<BaseShareTracker> m_legacy_tracker;
    hashrate::HashrateTracker* m_hashrate_tracker;
    difficulty::DifficultyAdjustmentEngine* m_difficulty_engine;
    
public:
    /**
     * @brief Construct bridge with tracking components
     * @param hashrate_tracker Hashrate tracker instance
     * @param difficulty_engine Difficulty adjustment engine
     */
    LegacyShareTrackerBridge(hashrate::HashrateTracker* hashrate_tracker, 
                           difficulty::DifficultyAdjustmentEngine* difficulty_engine);
    
    /**
     * @brief Process a share through both legacy and new systems
     * @param share The C2Pool share to process
     */
    void process_share(const C2PoolShare& share);
    
    /**
     * @brief Get share count from legacy tracker
     * @return Number of shares tracked by legacy system
     */
    uint64_t get_legacy_share_count() const;
    
    /**
     * @brief Get hashrate from legacy tracker
     * @return Hashrate estimate from legacy system
     */
    double get_legacy_hashrate() const;
    
    /**
     * @brief Get combined statistics from both systems
     * @return JSON object with comprehensive statistics
     */
    nlohmann::json get_combined_statistics() const;
    
    /**
     * @brief Sync state between legacy and new systems
     */
    void sync_systems();
    
private:
    /**
     * @brief Convert C2PoolShare to legacy format
     * @param share Modern share structure
     * @return Legacy-compatible share data
     */
    void convert_to_legacy_format(const C2PoolShare& share);
};

} // namespace bridge
} // namespace c2pool
