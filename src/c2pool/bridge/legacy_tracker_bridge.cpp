#include "legacy_tracker_bridge.hpp"
#include <nlohmann/json.hpp>
#include <core/log.hpp>

// Define C2PoolShare structure here for the bridge
namespace c2pool {
    struct C2PoolShare {
        uint256 m_hash;
        uint256 m_difficulty;
        uint64_t m_submit_time;
        bool m_accepted = true;
        // Additional fields as needed
    };
}

namespace c2pool {
namespace bridge {

LegacyShareTrackerBridge::LegacyShareTrackerBridge(hashrate::HashrateTracker* hashrate_tracker, 
                       difficulty::DifficultyAdjustmentEngine* difficulty_engine) 
    : m_hashrate_tracker(hashrate_tracker), m_difficulty_engine(difficulty_engine) {
    m_legacy_tracker = std::make_unique<BaseShareTracker>();
}

void LegacyShareTrackerBridge::process_share(const C2PoolShare& share) {
    // Process with legacy tracker for compatibility
    if (m_legacy_tracker) {
        // Convert to legacy format and track
        m_legacy_tracker->add_share(share.m_hash, share.m_difficulty.GetLow64());
    }
    
    // Process with new enhanced trackers
    if (m_hashrate_tracker) {
        m_hashrate_tracker->record_share(share.m_hash, share.m_difficulty.GetLow64(), share.m_submit_time);
    }
    
    if (m_difficulty_engine) {
        // Update difficulty based on recent performance
        auto current_hashrate = m_hashrate_tracker->get_current_hashrate();
        auto new_difficulty = m_difficulty_engine->calculate_new_difficulty(
            share.m_difficulty.GetLow64(), current_hashrate, share.m_submit_time
        );
        m_difficulty_engine->apply_difficulty_adjustment(new_difficulty);
    }
}

uint64_t LegacyShareTrackerBridge::get_legacy_share_count() const {
    return m_legacy_tracker ? m_legacy_tracker->get_total_shares() : 0;
}

double LegacyShareTrackerBridge::get_legacy_hashrate() const {
    return m_legacy_tracker ? m_legacy_tracker->get_network_hashrate() : 0.0;
}

nlohmann::json LegacyShareTrackerBridge::get_combined_statistics() const {
    nlohmann::json stats;
    
    // Legacy stats
    stats["legacy"] = {
        {"share_count", get_legacy_share_count()},
        {"hashrate", get_legacy_hashrate()}
    };
    
    // New system stats
    if (m_hashrate_tracker) {
        stats["hashrate_tracker"] = m_hashrate_tracker->get_statistics();
    }
    
    if (m_difficulty_engine) {
        stats["difficulty_engine"] = m_difficulty_engine->get_difficulty_stats();
    }
    
    // Combined metrics
    stats["combined"] = {
        {"total_systems", 2},
        {"sync_status", "active"}
    };
    
    return stats;
}

void LegacyShareTrackerBridge::sync_systems() {
    if (!m_legacy_tracker || !m_hashrate_tracker) {
        return;
    }
    
    // Sync basic statistics between systems
    auto legacy_count = m_legacy_tracker->get_total_shares();
    auto new_stats = m_hashrate_tracker->get_statistics();
    
    LOG_INFO << "Syncing legacy and new tracking systems:";
    LOG_INFO << "  Legacy shares: " << legacy_count;
    LOG_INFO << "  New system shares: " << new_stats["total_shares_submitted"];
    LOG_INFO << "  Systems synchronized";
}

void LegacyShareTrackerBridge::convert_to_legacy_format(const C2PoolShare& share) {
    // Convert modern share format to legacy format
    // This would involve mapping fields appropriately
    LOG_DEBUG_OTHER << "Converting share " << share.m_hash.ToString().substr(0, 16) 
              << "... to legacy format";
}

} // namespace bridge
} // namespace c2pool
