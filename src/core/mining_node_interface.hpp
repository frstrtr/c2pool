#pragma once

#include <string>
#include <memory>
#include <cstdint>
#include <nlohmann/json.hpp>
#include <core/uint256.hpp>

namespace core {

/// Interface for mining node integration with web server
/// This allows the web server to communicate with c2pool node for difficulty adjustment
class IMiningNode {
public:
    virtual ~IMiningNode() = default;
    
    // Difficulty and hashrate tracking
    virtual void track_share_submission(const std::string& session_id, double difficulty) = 0;
    virtual nlohmann::json get_difficulty_stats() const = 0;
    virtual nlohmann::json get_hashrate_stats() const = 0;
    
    // Share management
    virtual void add_local_share(const uint256& hash, const uint256& prev_hash, const uint256& target) = 0;
    virtual uint64_t get_total_shares() const = 0;
    
    // Network info
    virtual size_t get_connected_peers_count() const = 0;
    
    // Statistics
    virtual void log_sharechain_stats() = 0;
};

} // namespace core
