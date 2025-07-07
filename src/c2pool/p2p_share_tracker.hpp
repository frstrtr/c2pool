#pragma once

#include "share_types.hpp"
#include <core/log.hpp>
#include <nlohmann/json.hpp>
#include <deque>
#include <mutex>
#include <set>
#include <map>
#include <ctime>

namespace c2pool {

/**
 * @brief Tracker for P2P shares from cross-node communication
 * 
 * Handles tracking, verification, and forwarding of shares
 * received from other C2Pool nodes and P2Pool networks.
 */
class P2PShareTracker {
private:
    struct P2PShareSubmission {
        uint64_t timestamp;
        double difficulty;
        bool verified;
        bool forwarded;
        std::string peer_address;
        std::string network_id;
    };
    
    std::deque<P2PShareSubmission> recent_submissions_;
    mutable std::mutex submissions_mutex_;
    
    // Peer tracking
    std::map<std::string, uint64_t> peer_last_seen_;
    std::map<std::string, uint64_t> peer_share_counts_;
    std::map<std::string, std::string> peer_network_map_;
    
    // Statistics
    uint64_t total_p2p_shares_received_ = 0;
    uint64_t total_p2p_shares_verified_ = 0;
    uint64_t total_p2p_shares_forwarded_ = 0;
    uint64_t total_p2p_shares_rejected_ = 0;
    
public:
    /**
     * @brief Record a new P2P share reception
     */
    void record_p2p_share(const P2PShare& share) {
        record_reception(share.get_difficulty_value(), share.m_verified, 
                        share.m_forwarded, share.m_peer_address, share.m_network_id);
    }
    
    /**
     * @brief Record a P2P share reception with parameters
     */
    void record_reception(double difficulty, bool verified, bool forwarded = false,
                         const std::string& peer_address = "", 
                         const std::string& network_id = "") {
        std::lock_guard<std::mutex> lock(submissions_mutex_);
        
        uint64_t now = static_cast<uint64_t>(std::time(nullptr));
        recent_submissions_.push_back({now, difficulty, verified, forwarded, peer_address, network_id});
        
        // Keep only submissions from last hour
        while (!recent_submissions_.empty() && 
               recent_submissions_.front().timestamp < now - 3600) {
            recent_submissions_.pop_front();
        }
        
        total_p2p_shares_received_++;
        if (verified) {
            total_p2p_shares_verified_++;
        } else {
            total_p2p_shares_rejected_++;
        }
        
        if (forwarded) {
            total_p2p_shares_forwarded_++;
        }
        
        // Update peer tracking
        if (!peer_address.empty()) {
            peer_last_seen_[peer_address] = now;
            peer_share_counts_[peer_address]++;
            if (!network_id.empty()) {
                peer_network_map_[peer_address] = network_id;
            }
        }
        
        LOG_DEBUG_OTHER << "Recorded P2P share: difficulty=" << difficulty 
                       << ", verified=" << verified << ", peer=" << peer_address
                       << ", network=" << network_id;
    }
    
    /**
     * @brief Record that a share was forwarded to other peers
     */
    void record_forward(const std::string& peer_address = "") {
        std::lock_guard<std::mutex> lock(submissions_mutex_);
        total_p2p_shares_forwarded_++;
        
        LOG_DEBUG_OTHER << "Recorded P2P share forward" 
                       << (peer_address.empty() ? "" : " to " + peer_address);
    }
    
    /**
     * @brief Get comprehensive P2P share statistics
     */
    nlohmann::json get_statistics() const {
        std::lock_guard<std::mutex> lock(submissions_mutex_);
        
        uint64_t now = static_cast<uint64_t>(std::time(nullptr));
        
        // Calculate verification rate for last hour
        uint64_t recent_received = 0;
        uint64_t recent_verified = 0;
        uint64_t recent_forwarded = 0;
        
        for (const auto& submission : recent_submissions_) {
            if (submission.timestamp > now - 3600) { // Last hour
                recent_received++;
                if (submission.verified) recent_verified++;
                if (submission.forwarded) recent_forwarded++;
            }
        }
        
        double verification_rate = recent_received > 0 ? 
            (double)recent_verified / recent_received * 100.0 : 0.0;
        
        double forward_rate = recent_received > 0 ?
            (double)recent_forwarded / recent_received * 100.0 : 0.0;
        
        return {
            {"type", "p2p_shares"},
            {"total_p2p_shares_received", total_p2p_shares_received_},
            {"total_p2p_shares_verified", total_p2p_shares_verified_},
            {"total_p2p_shares_forwarded", total_p2p_shares_forwarded_},
            {"total_p2p_shares_rejected", total_p2p_shares_rejected_},
            {"verification_rate_1h", verification_rate},
            {"forward_rate_1h", forward_rate},
            {"recent_submissions_count", recent_submissions_.size()},
            {"active_peers_count", get_active_peers().size()},
            {"total_known_peers", peer_last_seen_.size()}
        };
    }
    
    /**
     * @brief Get list of active peer addresses
     */
    std::vector<std::string> get_active_peers() const {
        std::lock_guard<std::mutex> lock(submissions_mutex_);
        
        uint64_t now = static_cast<uint64_t>(std::time(nullptr));
        std::vector<std::string> active_peers;
        
        for (const auto& [peer_address, last_seen] : peer_last_seen_) {
            if (last_seen > now - 600) { // Last 10 minutes
                active_peers.push_back(peer_address);
            }
        }
        
        return active_peers;
    }
    
    /**
     * @brief Get detailed peer information
     */
    nlohmann::json get_peer_info() const {
        std::lock_guard<std::mutex> lock(submissions_mutex_);
        
        uint64_t now = static_cast<uint64_t>(std::time(nullptr));
        nlohmann::json peers = nlohmann::json::array();
        
        for (const auto& [peer_address, last_seen] : peer_last_seen_) {
            bool is_active = (last_seen > now - 600);
            uint64_t share_count = peer_share_counts_.count(peer_address) ? 
                                  peer_share_counts_.at(peer_address) : 0;
            std::string network = peer_network_map_.count(peer_address) ?
                                 peer_network_map_.at(peer_address) : "unknown";
            
            peers.push_back({
                {"address", peer_address},
                {"network", network},
                {"last_seen", last_seen},
                {"seconds_ago", now - last_seen},
                {"is_active", is_active},
                {"total_shares", share_count}
            });
        }
        
        return peers;
    }
    
    /**
     * @brief Get network distribution of peers
     */
    std::map<std::string, uint64_t> get_network_distribution() const {
        std::lock_guard<std::mutex> lock(submissions_mutex_);
        
        std::map<std::string, uint64_t> network_counts;
        uint64_t now = static_cast<uint64_t>(std::time(nullptr));
        
        for (const auto& [peer_address, network_id] : peer_network_map_) {
            if (peer_last_seen_.count(peer_address) && 
                peer_last_seen_.at(peer_address) > now - 600) { // Active in last 10 minutes
                network_counts[network_id]++;
            }
        }
        
        return network_counts;
    }
    
    /**
     * @brief Check if a peer is known and active
     */
    bool is_peer_active(const std::string& peer_address) const {
        std::lock_guard<std::mutex> lock(submissions_mutex_);
        
        if (!peer_last_seen_.count(peer_address)) {
            return false;
        }
        
        uint64_t now = static_cast<uint64_t>(std::time(nullptr));
        return peer_last_seen_.at(peer_address) > now - 600; // Active in last 10 minutes
    }
    
    /**
     * @brief Get share reception rate for a specific peer
     */
    double get_peer_share_rate(const std::string& peer_address) const {
        std::lock_guard<std::mutex> lock(submissions_mutex_);
        
        uint64_t now = static_cast<uint64_t>(std::time(nullptr));
        uint64_t shares_in_window = 0;
        uint64_t time_window = 3600; // 1 hour
        
        for (const auto& submission : recent_submissions_) {
            if (submission.peer_address == peer_address && 
                submission.timestamp > now - time_window) {
                shares_in_window++;
            }
        }
        
        return static_cast<double>(shares_in_window) / time_window * 3600.0; // shares per hour
    }
    
    /**
     * @brief Clean up old peer data
     */
    void cleanup_old_peers() {
        std::lock_guard<std::mutex> lock(submissions_mutex_);
        
        uint64_t now = static_cast<uint64_t>(std::time(nullptr));
        uint64_t cleanup_threshold = now - 86400; // 24 hours
        
        auto it = peer_last_seen_.begin();
        while (it != peer_last_seen_.end()) {
            if (it->second < cleanup_threshold) {
                std::string peer_address = it->first;
                peer_share_counts_.erase(peer_address);
                peer_network_map_.erase(peer_address);
                it = peer_last_seen_.erase(it);
            } else {
                ++it;
            }
        }
    }
};

} // namespace c2pool
