#pragma once

#include <memory>
#include <map>
#include <impl/ltc/node.hpp>
#include <impl/ltc/peer.hpp>
#include <c2pool/storage/sharechain_storage.hpp>
#include <c2pool/hashrate/tracker.hpp>
#include <c2pool/difficulty/adjustment_engine.hpp>
#include <core/mining_node_interface.hpp>
#include <core/message.hpp>
#include <core/common.hpp>
#include <nlohmann/json.hpp>

namespace c2pool {
namespace node {

/**
 * @brief Enhanced C2Pool node with automatic difficulty adjustment and hashrate tracking
 * 
 * Integrates all the enhanced features while maintaining compatibility with
 * the existing LTC sharechain infrastructure and c2pool network protocol.
 */
class EnhancedC2PoolNode {
private:
    std::unique_ptr<storage::SharechainStorage> m_storage;
    uint64_t m_shares_since_save = 0;
    difficulty::DifficultyAdjustmentEngine m_difficulty_adjustment_engine;
    std::unique_ptr<hashrate::HashrateTracker> m_hashrate_tracker;
    
    // Basic node infrastructure
    boost::asio::io_context* m_context = nullptr;
    ltc::Config* m_config = nullptr;
    ltc::ShareChain* m_chain = nullptr; // Placeholder for sharechain
    std::map<NetService, std::shared_ptr<ltc::Peer>> m_connections;
    
public:
    /**
     * @brief Default constructor
     */
    EnhancedC2PoolNode();
    
    /**
     * @brief Construct with IO context and configuration
     * @param ctx Boost ASIO IO context
     * @param config LTC configuration
     */
    EnhancedC2PoolNode(boost::asio::io_context* ctx, ltc::Config* config);
    
    /**
     * @brief Destructor with cleanup
     */
    ~EnhancedC2PoolNode() = default;
    
    // ICommunicator implementation
    void handle(std::unique_ptr<RawMessage> rmsg, const NetService& service);
    
    // IMiningNode implementation
    std::string get_mining_work(const std::string& address);
    bool submit_mining_work(const std::string& work_data);
    nlohmann::json get_mining_stats();
    double get_current_difficulty();
    
    /**
     * @brief Add shares to the chain with persistence
     * @param shares Vector of LTC shares to add
     */
    void add_shares_to_chain(const std::vector<ltc::ShareType>& shares);
    
    /**
     * @brief Start listening on the specified port
     * @param port Port to listen on
     */
    void listen(int port);
    
    /**
     * @brief Shutdown node gracefully
     */
    void shutdown();
    
    /**
     * @brief Log comprehensive sharechain statistics
     */
    void log_sharechain_stats();
    
    /**
     * @brief Track mining_share submission for mining interface
     * @param session_id Session identifier
     * @param difficulty MiningShare difficulty
     */
    void track_mining_share_submission(const std::string& session_id, double difficulty);
    
    /**
     * @brief Get difficulty statistics
     * @return JSON object with difficulty stats
     */
    nlohmann::json get_difficulty_stats() const;
    
    /**
     * @brief Get hashrate statistics
     * @return JSON object with hashrate stats
     */
    nlohmann::json get_hashrate_stats() const;
    
    /**
     * @brief Get total number of mining_shares in chain
     * @return MiningShare count
     */
    uint64_t get_total_mining_shares() const;
    
    /**
     * @brief Get number of connected peers
     * @return Peer count
     */
    size_t get_connected_peers_count() const;
    
    /**
     * @brief Get storage manager
     * @return Pointer to storage manager
     */
    storage::SharechainStorage* get_storage() const { return m_storage.get(); }
    
    /**
     * @brief Get hashrate tracker
     * @return Pointer to hashrate tracker
     */
    hashrate::HashrateTracker* get_hashrate_tracker() const { return m_hashrate_tracker.get(); }
    
    /**
     * @brief Get difficulty engine
     * @return Reference to difficulty adjustment engine
     */
    difficulty::DifficultyAdjustmentEngine& get_difficulty_engine() { return m_difficulty_adjustment_engine; }
};

} // namespace node
} // namespace c2pool
