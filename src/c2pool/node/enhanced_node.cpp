#include "enhanced_node.hpp"
#include <core/log.hpp>

namespace c2pool {
namespace node {

EnhancedC2PoolNode::EnhancedC2PoolNode() {
    m_hashrate_tracker = std::make_unique<hashrate::HashrateTracker>();
    m_storage = std::make_unique<storage::SharechainStorage>("testnet");
    
    LOG_INFO << "Enhanced C2Pool node initialized with default configuration";
    LOG_INFO << "  - Automatic difficulty adjustment";
    LOG_INFO << "  - Real-time hashrate tracking";
    LOG_INFO << "  - Persistent storage (testnet)";
}

EnhancedC2PoolNode::EnhancedC2PoolNode(boost::asio::io_context* ctx, ltc::Config* config) 
    : m_context(ctx), m_config(config) 
{
    // Initialize components
    m_hashrate_tracker = std::make_unique<hashrate::HashrateTracker>();
    
    // Initialize storage
    std::string network = config ? (config->m_testnet ? "testnet" : "mainnet") : "testnet";
    m_storage = std::make_unique<storage::SharechainStorage>(network);
    
    // Only load sharechain if we have a valid chain pointer
    if (m_chain) {
        if (m_storage->load_sharechain(*m_chain)) {
            LOG_INFO << "Restored sharechain from disk";
            log_sharechain_stats();
        }
        
        // Schedule periodic saves
        m_storage->schedule_periodic_save(*m_chain, *ctx);
    }
    
    LOG_INFO << "Enhanced C2Pool node initialized with:";
    LOG_INFO << "  - Automatic difficulty adjustment";
    LOG_INFO << "  - Real-time hashrate tracking";
    LOG_INFO << "  - Persistent storage (" << network << ")";
}

void EnhancedC2PoolNode::handle(std::unique_ptr<RawMessage> rmsg, const NetService& service) {
    LOG_INFO << "Enhanced C2Pool node received message: " << rmsg->m_command 
             << " from " << service.to_string();
    
    // Delegate to LTC node implementation for protocol handling
    // Additional enhanced processing could be added here
}

void EnhancedC2PoolNode::add_shares_to_chain(const std::vector<ltc::ShareType>& shares) {
    for (const auto& share : shares) {
        // Add to LTC chain using proper methods
        // Note: This would need proper integration with LTC sharechain
        
        // Process through bridge for enhanced tracking
        // if (m_bridge) {
            // Convert LTC share to C2PoolShare format for processing
            // This is a simplified conversion
            // c2pool::C2PoolShare c2pool_share;
            // share.USE([&](auto* typed_share) {
            //     c2pool_share.m_hash = typed_share->m_hash;
            //     c2pool_share.m_submit_time = static_cast<uint64_t>(std::time(nullptr));
            //     // Additional field mapping as needed
            // });
            
            // m_bridge->process_share(c2pool_share);
        // }
    }
    
    // Increment shares counter and save if threshold reached
    m_shares_since_save += shares.size();
    if (m_shares_since_save >= 100) { // Save every 100 new shares
        LOG_INFO << "Saving sharechain due to threshold (" << m_shares_since_save << " new shares)";
        m_storage->save_sharechain(*m_chain);
        m_shares_since_save = 0;
    }
}

void node::EnhancedC2PoolNode::listen(int port) {
    LOG_INFO << "Enhanced C2Pool node starting to listen on port " << port;
    // Simplified listen implementation - would need proper socket setup
}

void node::EnhancedC2PoolNode::shutdown()
{
    LOG_INFO << "Shutting down Enhanced C2Pool node, saving sharechain...";
    
    if (m_storage && m_chain) {
        m_storage->save_sharechain(*m_chain);
        m_storage->log_storage_stats();
    }
}

void node::EnhancedC2PoolNode::log_sharechain_stats()
{
    if (!m_chain) return;
    
    // Get stats using available LTC sharechain methods
    uint64_t total_mining_shares = get_total_mining_shares();
    
    LOG_INFO << "Enhanced C2Pool Sharechain stats:";
    LOG_INFO << "  Total mining_shares: " << total_mining_shares;
    LOG_INFO << "  Connected peers: " << get_connected_peers_count();
    LOG_INFO << "  Storage: " << (m_storage && m_storage->is_available() ? "enabled" : "disabled");
    
    // Log hashrate and difficulty statistics
    if (m_hashrate_tracker) {
        auto stats = m_hashrate_tracker->get_statistics();
        LOG_INFO << "  Current difficulty: " << stats["current_difficulty"];
        LOG_INFO << "  Current hashrate: " << stats["current_hashrate"] << " H/s";
        LOG_INFO << "  Total mining_shares submitted: " << stats["total_shares_submitted"];
        LOG_INFO << "  Total mining_shares accepted: " << stats["total_shares_accepted"];
        LOG_INFO << "  Acceptance rate (last hour): " << stats["acceptance_rate_1h"] << "%";
    }
    
    // Log difficulty adjustment stats
    LOG_INFO << "  Difficulty Adjustment Stats:";
    auto diff_stats = m_difficulty_adjustment_engine.get_difficulty_stats();
    LOG_INFO << "    Pool difficulty: " << diff_stats["pool_difficulty"];
    LOG_INFO << "    Network difficulty: " << diff_stats["network_difficulty"];
    LOG_INFO << "    Mining_shares since adjustment: " << diff_stats["shares_since_adjustment"];
    LOG_INFO << "    Target mining_shares per adjustment: " << diff_stats["target_shares_per_adjustment"];
}

void node::EnhancedC2PoolNode::track_mining_share_submission(const std::string& session_id, double difficulty) {
    if (m_hashrate_tracker) {
        m_hashrate_tracker->record_share_submission(difficulty, true); // Assume accepted for now
    }
    
    LOG_DEBUG_OTHER << "Tracked mining_share submission for session " << session_id 
              << " with difficulty " << difficulty;
}

nlohmann::json node::EnhancedC2PoolNode::get_difficulty_stats() const {
    return m_difficulty_adjustment_engine.get_difficulty_stats();
}

nlohmann::json node::EnhancedC2PoolNode::get_hashrate_stats() const {
    if (m_hashrate_tracker) {
        return m_hashrate_tracker->get_statistics();
    }
    return nlohmann::json{{"global_hashrate", 0.0}};
}

uint64_t node::EnhancedC2PoolNode::get_total_mining_shares() const {
    return m_chain ? 1000 : 0; // Placeholder - would need proper implementation with LTC chain
}

size_t node::EnhancedC2PoolNode::get_connected_peers_count() const {
    return m_connections.size();
}

// Mining interface implementations
std::string node::EnhancedC2PoolNode::get_mining_work(const std::string& address) {
    // Generate work based on current difficulty
    auto current_difficulty = m_hashrate_tracker->get_current_difficulty();
    auto pool_target = m_difficulty_adjustment_engine.get_pool_target();
    
    // Create work template (simplified)
    nlohmann::json work = {
        {"target", pool_target.ToString()},
        {"difficulty", current_difficulty},
        {"address", address},
        {"timestamp", static_cast<uint64_t>(std::time(nullptr))}
    };
    
    return work.dump();
}

bool node::EnhancedC2PoolNode::submit_mining_work(const std::string& work_data) {
    try {
        auto work = nlohmann::json::parse(work_data);
        double difficulty = work.value("difficulty", 1.0);
        
        // Track the submission
        m_hashrate_tracker->record_share_submission(difficulty, true);
        
        LOG_INFO << "Mining work submitted with difficulty " << difficulty;
        return true;
        
    } catch (const std::exception& e) {
        LOG_ERROR << "Failed to submit mining work: " << e.what();
        return false;
    }
}

nlohmann::json node::EnhancedC2PoolNode::get_mining_stats() {
    nlohmann::json stats;
    
    // Combine all statistics
    stats["hashrate"] = get_hashrate_stats();
    stats["difficulty"] = get_difficulty_stats();
    stats["mining_shares"] = {
        {"total", get_total_mining_shares()},
        {"since_save", m_shares_since_save}
    };
    stats["network"] = {
        {"connected_peers", get_connected_peers_count()}
    };
    
    return stats;
}

double node::EnhancedC2PoolNode::get_current_difficulty() {
    return m_hashrate_tracker->get_current_difficulty();
}

} // namespace node
} // namespace c2pool
