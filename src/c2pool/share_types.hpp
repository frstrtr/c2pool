#pragma once

#include <btclibs/uint256.h>
#include <string>
#include <chrono>

namespace c2pool {

/**
 * @brief Mining share from physical miners connecting via Stratum
 * 
 * These shares represent work submitted by actual mining hardware
 * connected to the C2Pool node via Stratum protocol on port 8084.
 */
struct MiningShare {
    uint256 m_hash;                 // Share hash
    uint256 m_prev_hash;            // Previous share hash
    uint256 m_difficulty;           // Share difficulty
    uint64_t m_submit_time;         // Timestamp when submitted
    std::string m_miner_address;    // Physical miner payout address
    std::string m_miner_session_id; // Stratum session ID
    std::string m_job_id;           // Mining job ID
    std::string m_nonce;            // Miner nonce
    std::string m_extranonce2;      // Extra nonce 2
    uint64_t m_height;              // Blockchain height
    uint256 m_work;                 // Work value
    uint256 m_target;               // Target for this share
    bool m_accepted;                // Whether share was accepted
    
    MiningShare() = default;
    
    MiningShare(const uint256& hash, const uint256& prev_hash, const uint256& difficulty, 
               uint64_t submit_time, const std::string& miner_address)
        : m_hash(hash), m_prev_hash(prev_hash), m_difficulty(difficulty), 
          m_submit_time(submit_time), m_miner_address(miner_address), 
          m_accepted(false), m_height(0) {}
    
    // Validation methods
    bool is_valid_format() const {
        return !m_hash.IsNull() && !m_miner_address.empty() && m_submit_time > 0;
    }
    
    double get_difficulty_value() const {
        return static_cast<double>(m_difficulty.GetLow64());
    }
    
    std::string to_string() const {
        return "MiningShare{hash=" + m_hash.ToString().substr(0, 16) + 
               "..., miner=" + m_miner_address + 
               ", difficulty=" + std::to_string(get_difficulty_value()) + 
               ", accepted=" + (m_accepted ? "true" : "false") + "}";
    }
};

/**
 * @brief P2P share from cross-node communication with other C2Pool/P2Pool nodes
 * 
 * These shares represent cross-node communication and sharechain synchronization
 * between different C2Pool nodes and P2Pool networks.
 */
struct P2PShare {
    uint256 m_hash;                 // Share hash
    uint256 m_prev_hash;            // Previous share hash in sharechain
    uint256 m_difficulty;           // Share difficulty
    uint64_t m_submit_time;         // Timestamp when received
    std::string m_peer_address;     // Source peer address/node ID
    std::string m_network_id;       // Network identifier (LTC, BTC, etc.)
    std::string m_protocol_version; // P2Pool protocol version
    uint64_t m_height;              // Sharechain height
    uint256 m_work;                 // Cumulative work
    uint256 m_target;               // Target for this share
    bool m_verified;                // Whether share was verified
    bool m_forwarded;               // Whether share was forwarded to other peers
    
    P2PShare() = default;
    
    P2PShare(const uint256& hash, const uint256& prev_hash, const uint256& difficulty, 
            uint64_t submit_time, const std::string& peer_address, const std::string& network_id)
        : m_hash(hash), m_prev_hash(prev_hash), m_difficulty(difficulty), 
          m_submit_time(submit_time), m_peer_address(peer_address), m_network_id(network_id),
          m_verified(false), m_forwarded(false), m_height(0) {}
    
    // Validation methods
    bool is_valid_format() const {
        return !m_hash.IsNull() && !m_peer_address.empty() && 
               !m_network_id.empty() && m_submit_time > 0;
    }
    
    double get_difficulty_value() const {
        return static_cast<double>(m_difficulty.GetLow64());
    }
    
    std::string to_string() const {
        return "P2PShare{hash=" + m_hash.ToString().substr(0, 16) + 
               "..., peer=" + m_peer_address + 
               ", network=" + m_network_id +
               ", difficulty=" + std::to_string(get_difficulty_value()) + 
               ", verified=" + (m_verified ? "true" : "false") + "}";
    }
};

/**
 * @brief Share source enumeration for tracking
 */
enum class ShareSource {
    MINING_HARDWARE,    // From physical miners via Stratum
    P2P_NETWORK,        // From peer nodes via P2Pool protocol
    LOCAL_GENERATION,   // Generated locally
    UNKNOWN
};

/**
 * @brief Generic share container that can hold either type
 */
struct ShareContainer {
    ShareSource source;
    union {
        MiningShare mining_share;
        P2PShare p2p_share;
    };
    
    ShareContainer(const MiningShare& share) : source(ShareSource::MINING_HARDWARE) {
        new(&mining_share) MiningShare(share);
    }
    
    ShareContainer(const P2PShare& share) : source(ShareSource::P2P_NETWORK) {
        new(&p2p_share) P2PShare(share);
    }
    
    ~ShareContainer() {
        if (source == ShareSource::MINING_HARDWARE) {
            mining_share.~MiningShare();
        } else if (source == ShareSource::P2P_NETWORK) {
            p2p_share.~P2PShare();
        }
    }
    
    // Copy constructor
    ShareContainer(const ShareContainer& other) : source(other.source) {
        if (source == ShareSource::MINING_HARDWARE) {
            new(&mining_share) MiningShare(other.mining_share);
        } else if (source == ShareSource::P2P_NETWORK) {
            new(&p2p_share) P2PShare(other.p2p_share);
        }
    }
    
    // Assignment operator
    ShareContainer& operator=(const ShareContainer& other) {
        if (this != &other) {
            this->~ShareContainer();
            source = other.source;
            if (source == ShareSource::MINING_HARDWARE) {
                new(&mining_share) MiningShare(other.mining_share);
            } else if (source == ShareSource::P2P_NETWORK) {
                new(&p2p_share) P2PShare(other.p2p_share);
            }
        }
        return *this;
    }
    
    uint256 get_hash() const {
        switch (source) {
            case ShareSource::MINING_HARDWARE:
                return mining_share.m_hash;
            case ShareSource::P2P_NETWORK:
                return p2p_share.m_hash;
            default:
                return uint256::ZERO;
        }
    }
    
    double get_difficulty() const {
        switch (source) {
            case ShareSource::MINING_HARDWARE:
                return mining_share.get_difficulty_value();
            case ShareSource::P2P_NETWORK:
                return p2p_share.get_difficulty_value();
            default:
                return 0.0;
        }
    }
    
    std::string to_string() const {
        switch (source) {
            case ShareSource::MINING_HARDWARE:
                return "Mining" + mining_share.to_string();
            case ShareSource::P2P_NETWORK:
                return "P2P" + p2p_share.to_string();
            default:
                return "UnknownShare{}";
        }
    }
};

} // namespace c2pool
