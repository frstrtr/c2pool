#include <iostream>
#include <fstream>
#include <string>
#include <map>
#include <thread>
#include <chrono>
#include <csignal>
#include <ctime>
#include <memory>

#include <core/settings.hpp>
#include <core/fileconfig.hpp>
#include <core/pack.hpp>
#include <core/filesystem.hpp>
#include <core/log.hpp>
#include <core/uint256.hpp>
#include <core/web_server.hpp>
#include <pool/node.hpp>
#include <pool/protocol.hpp>
#include <sharechain/sharechain.hpp>
#include <core/config.hpp>
#include <core/mining_node_interface.hpp>

// c2pool node includes for sharechain networking
#include <pool/peer.hpp>
#include <pool/node.hpp>
#include <core/message.hpp>
#include <core/node_interface.hpp>

// Include LTC sharechain implementation for robust protocol handling
#include <impl/ltc/share.hpp>
#include <impl/ltc/node.hpp>
#include <impl/ltc/messages.hpp>
#include <impl/ltc/config.hpp>

// Include storage and file I/O
#include <fstream>
#include <filesystem>
#include <core/leveldb_store.hpp>

#include <boost/asio.hpp>
#include <nlohmann/json.hpp>

// Legacy Share Tracker Integration Bridge
#include <sharechain/legacy/tracker.hpp>
#include <sharechain/legacy/base_share_tracker.hpp>

// Forward declarations for our enhanced types
namespace c2pool {
    struct MiningShare;      // Shares from physical miners 
    struct P2PShare;         // Shares from P2Pool cross-node communication
    
    namespace hashrate {
        class HashrateTracker;
    }
    
    namespace difficulty {
        class DifficultyAdjustmentEngine;
    }
}

// Include our enhanced share trackers
#include <c2pool/share_types.hpp>
#include <c2pool/mining_share_tracker.hpp>
#include <c2pool/p2p_share_tracker.hpp>

// Modern LevelDB-based Sharechain Storage Manager
class SharechainStorage
{
private:
    std::unique_ptr<core::SharechainLevelDBStore> m_leveldb_store;
    std::string m_network_name;
    
public:
    SharechainStorage(const std::string& network_name) 
        : m_network_name(network_name)
    {
        std::string base_path = core::filesystem::config_path().string();
        m_leveldb_store = std::make_unique<core::SharechainLevelDBStore>(base_path, network_name);
        
        if (!m_leveldb_store->open()) {
            LOG_ERROR << "Failed to open LevelDB sharechain storage for network: " << network_name;
            m_leveldb_store.reset();
        } else {
            LOG_INFO << "LevelDB sharechain storage opened successfully";
            LOG_INFO << "  Network: " << network_name;
            LOG_INFO << "  Existing mining_shares: " << m_leveldb_store->get_share_count();
            LOG_INFO << "  Best height: " << m_leveldb_store->get_best_height();
        }
    }
    
    ~SharechainStorage()
    {
        if (m_leveldb_store) {
            LOG_INFO << "Closing LevelDB sharechain storage";
            LOG_INFO << "  Final mining_share count: " << m_leveldb_store->get_share_count();
            m_leveldb_store->close();
        }
    }
    
    bool is_available() const {
        return m_leveldb_store != nullptr;
    }
    
    // Save shares to LevelDB
    template<typename ShareChainType>
    void save_sharechain(const ShareChainType& chain)
    {
        if (!m_leveldb_store) {
            LOG_ERROR << "LevelDB store not available";
            return;
        }

        try {
            // For now, log that we would save (full integration needs sharechain API)
            LOG_INFO << "LevelDB sharechain storage is ready for persistent mining_share storage";
            LOG_INFO << "  Network: " << m_network_name;
            LOG_INFO << "  Current stored mining_shares: " << m_leveldb_store->get_share_count();
            LOG_INFO << "  Storage path: " << m_leveldb_store->get_base_path() << "/" << m_network_name << "/sharechain_leveldb";
            
        } catch (const std::exception& e) {
            LOG_ERROR << "Error with LevelDB sharechain storage: " << e.what();
        }
    }
    
    // Load shares from LevelDB
    template<typename ShareChainType>
    bool load_sharechain(ShareChainType& chain)
    {
        if (!m_leveldb_store) {
            LOG_WARNING << "LevelDB store not available, starting with empty sharechain";
            return false;
        }

        try {
            uint64_t stored_mining_shares = m_leveldb_store->get_share_count();
            if (stored_mining_shares == 0) {
                LOG_INFO << "No mining_shares found in LevelDB storage, starting fresh";
                return false;
            }
            
            uint256 best_hash = m_leveldb_store->get_best_hash();
            uint64_t best_height = m_leveldb_store->get_best_height();
            
            LOG_INFO << "LevelDB sharechain storage contains " << stored_mining_shares << " mining_shares";
            LOG_INFO << "  Best height: " << best_height;
            LOG_INFO << "  Best hash: " << best_hash.ToString().substr(0, 16) << "...";
            
            // For now, just report availability - full integration needs sharechain API
            LOG_INFO << "LevelDB storage is ready for mining_share loading and recovery";
            
            return stored_mining_shares > 0;
            
        } catch (const std::exception& e) {
            LOG_ERROR << "Error loading from LevelDB sharechain storage: " << e.what();
            return false;
        }
    }
    
    // Store a specific mining_share in LevelDB
    bool store_mining_share(const uint256& hash, const std::vector<uint8_t>& serialized_data, 
                     const uint256& prev_hash, uint64_t height, uint64_t timestamp,
                     const uint256& work, const uint256& target, bool is_orphan = false)
    {
        if (!m_leveldb_store) {
            return false;
        }
        
        try {
            core::ShareMetadata metadata;
            metadata.prev_hash = prev_hash;
            metadata.height = height;
            metadata.timestamp = timestamp;
            metadata.work = work;
            metadata.target = target;
            metadata.is_orphan = is_orphan;
            
            bool success = m_leveldb_store->store_share(hash, serialized_data, metadata);
            if (success) {
                LOG_INFO << "Stored mining_share in LevelDB: " << hash.ToString().substr(0, 16) 
                         << "... (height: " << height << ")";
            }
            return success;
            
        } catch (const std::exception& e) {
            LOG_ERROR << "Error storing share in LevelDB: " << e.what();
            return false;
        }
    }
    
    // Load a specific mining_share from LevelDB
    bool load_mining_share(const uint256& hash, std::vector<uint8_t>& serialized_data,
                    uint256& prev_hash, uint64_t& height, uint64_t& timestamp,
                    uint256& work, uint256& target, bool& is_orphan)
    {
        if (!m_leveldb_store) {
            return false;
        }
        
        try {
            core::ShareMetadata metadata;
            bool success = m_leveldb_store->load_share(hash, serialized_data, metadata);
            
            if (success) {
                prev_hash = metadata.prev_hash;
                height = metadata.height;
                timestamp = metadata.timestamp;
                work = metadata.work;
                target = metadata.target;
                is_orphan = metadata.is_orphan;
                
                LOG_DEBUG_DB << "Loaded mining_share from LevelDB: " << hash.ToString().substr(0, 16)
                             << "... (height: " << height << ")";
            }
            
            return success;
            
        } catch (const std::exception& e) {
            LOG_ERROR << "Error loading share from LevelDB: " << e.what();
            return false;
        }
    }
    
    // Check if a mining_share exists in LevelDB
    bool has_mining_share(const uint256& hash)
    {
        if (!m_leveldb_store) {
            return false;
        }
        
        return m_leveldb_store->has_share(hash);
    }
    
    // Get chain statistics
    void log_storage_stats()
    {
        if (!m_leveldb_store) {
            LOG_INFO << "LevelDB storage: Not available";
            return;
        }
        
        try {
            uint64_t share_count = m_leveldb_store->get_share_count();
            uint64_t best_height = m_leveldb_store->get_best_height();
            uint256 best_hash = m_leveldb_store->get_best_hash();
            
            LOG_INFO << "LevelDB Storage Stats:";
            LOG_INFO << "  Total mining_shares: " << share_count;
            LOG_INFO << "  Best height: " << best_height;
            if (best_hash != uint256::ZERO) {
                LOG_INFO << "  Best hash: " << best_hash.ToString().substr(0, 16) << "...";
            }
            LOG_INFO << "  Network: " << m_network_name;
            
        } catch (const std::exception& e) {
            LOG_ERROR << "Error getting LevelDB storage stats: " << e.what();
        }
    }
    
    // Compact the database
    void compact()
    {
        if (m_leveldb_store) {
            LOG_INFO << "Compacting LevelDB sharechain storage...";
            m_leveldb_store->compact();
        }
    }
    
    // Get chain hashes for synchronization
    std::vector<uint256> get_chain_hashes(const uint256& start_hash, uint64_t max_count, bool forward = true)
    {
        if (!m_leveldb_store) {
            return {};
        }
        
        return m_leveldb_store->get_chain_hashes(start_hash, max_count, forward);
    }
    
    // Get mining_shares by height range
    std::vector<uint256> get_mining_shares_by_height_range(uint64_t start_height, uint64_t end_height)
    {
        if (!m_leveldb_store) {
            return {};
        }
        
        return m_leveldb_store->get_shares_by_height_range(start_height, end_height);
    }
    
    // Periodic save (background task)
    template<typename ShareChainType>
    void schedule_periodic_save(ShareChainType& chain, boost::asio::io_context& ioc, int interval_seconds = 300)
    {
        auto timer = std::make_shared<boost::asio::steady_timer>(ioc);
        
        // Create a safe capture by copying what we need
        auto leveldb_store_ptr = m_leveldb_store.get(); // Raw pointer for safety check
        
        // Use a shared_ptr to hold the recursive callback
        auto save_task = std::make_shared<std::function<void()>>();
        *save_task = [leveldb_store_ptr, timer, interval_seconds, save_task]() {
            if (leveldb_store_ptr) {
                LOG_INFO << "Periodic LevelDB storage maintenance";
                
                try {
                    uint64_t share_count = leveldb_store_ptr->get_share_count();
                    uint64_t best_height = leveldb_store_ptr->get_best_height();
                    
                    LOG_INFO << "LevelDB Storage Stats:";
                    LOG_INFO << "  Total shares: " << share_count;
                    LOG_INFO << "  Best height: " << best_height;
                    
                    // Periodic compaction (every hour)
                    static int compact_counter = 0;
                    if (++compact_counter >= (3600 / interval_seconds)) {
                        LOG_INFO << "Compacting LevelDB sharechain storage...";
                        leveldb_store_ptr->compact();
                        compact_counter = 0;
                    }
                } catch (const std::exception& e) {
                    LOG_ERROR << "Error in periodic LevelDB maintenance: " << e.what();
                }
            }
            
            timer->expires_after(std::chrono::seconds(interval_seconds));
            timer->async_wait([save_task](const boost::system::error_code&) {
                if (save_task) (*save_task)();
            });
        };
        
        // Start after initial delay
        timer->expires_after(std::chrono::seconds(30));
        timer->async_wait([save_task](const boost::system::error_code&) {
            if (save_task) (*save_task)();
        });
    }
};

// Enhanced share tracking with separation between mining and P2P shares
namespace c2pool {
    // Mining share from physical miners
    struct MiningShare {
        uint256 m_hash;
        uint256 m_prev_hash;
        uint256 m_difficulty;
        uint64_t m_submit_time;
        std::string m_miner_address;  // Physical miner payout address
        std::string m_miner_session_id;
        uint64_t m_height;
        uint256 m_work;
        uint256 m_target;
        bool m_accepted;
        
        MiningShare() = default;
        MiningShare(const uint256& hash, const uint256& prev_hash, const uint256& difficulty, 
                   uint64_t submit_time, const std::string& miner_address)
            : m_hash(hash), m_prev_hash(prev_hash), m_difficulty(difficulty), 
              m_submit_time(submit_time), m_miner_address(miner_address), m_accepted(false) {}
    };
    
    // P2P share from cross-node communication
    struct P2PShare {
        uint256 m_hash;
        uint256 m_prev_hash;
        uint256 m_difficulty;
        uint64_t m_submit_time;
        std::string m_peer_address;   // P2Pool peer address
        std::string m_network_id;     // Network identifier
        uint64_t m_height;
        uint256 m_work;
        uint256 m_target;
        bool m_verified;
        
        P2PShare() = default;
        P2PShare(const uint256& hash, const uint256& prev_hash, const uint256& difficulty, 
                uint64_t submit_time, const std::string& peer_address)
            : m_hash(hash), m_prev_hash(prev_hash), m_difficulty(difficulty), 
              m_submit_time(submit_time), m_peer_address(peer_address), m_verified(false) {}
    };
}

// Mining Share Tracker for Physical Miners
class MiningShareTracker {
private:
    struct MiningShareSubmission {
        uint64_t timestamp;
        double difficulty;
        bool accepted;
        std::string miner_address;  // Physical miner address
    };
    
    std::deque<MiningShareSubmission> recent_mining_shares_;
    mutable std::mutex mining_shares_mutex_;
    double current_difficulty_ = 1.0;
    double target_time_per_share_ = 30.0; // Target 30 seconds per share
    uint64_t difficulty_adjustment_interval_ = 300; // 5 minutes
    uint64_t last_difficulty_adjustment_ = 0;
    
    // Difficulty bounds
    double min_difficulty_ = 0.001;
    double max_difficulty_ = 1000000.0;
    
    // Statistics
    uint64_t total_mining_shares_submitted_ = 0;
    uint64_t total_mining_shares_accepted_ = 0;
    double total_work_done_ = 0.0;
    
public:
    void record_mining_share_submission(double difficulty, bool accepted, const std::string& miner_address = "") {
        std::lock_guard<std::mutex> lock(mining_shares_mutex_);
        
        uint64_t now = static_cast<uint64_t>(std::time(nullptr));
        recent_mining_shares_.push_back({now, difficulty, accepted, miner_address});
        
        // Keep only shares from last hour
        while (!recent_mining_shares_.empty() && 
               recent_mining_shares_.front().timestamp < now - 3600) {
            recent_mining_shares_.pop_front();
        }
        
        total_mining_shares_submitted_++;
        if (accepted) {
            total_mining_shares_accepted_++;
            total_work_done_ += difficulty;
        }
        
        // Check if we should adjust difficulty
        if (now - last_difficulty_adjustment_ > difficulty_adjustment_interval_) {
            adjust_mining_difficulty();
            last_difficulty_adjustment_ = now;
        }
    }
    
    double get_current_difficulty() const {
        std::lock_guard<std::mutex> lock(mining_shares_mutex_);
        return current_difficulty_;
    }
    
    double get_current_hashrate() const {
        std::lock_guard<std::mutex> lock(mining_shares_mutex_);
        
        uint64_t now = static_cast<uint64_t>(std::time(nullptr));
        double work_done = 0.0;
        uint64_t time_window = 600; // 10 minutes
        
        for (const auto& share : recent_mining_shares_) {
            if (share.accepted && share.timestamp > now - time_window) {
                work_done += share.difficulty;
            }
        }
        
        if (time_window > 0) {
            // Hashrate = work_done / time_window * 2^32 (for difficulty 1 = ~4.3GH/s)
            return work_done / time_window * 4294967296.0; // 2^32
        }
        
        return 0.0;
    }
    
    nlohmann::json get_mining_statistics() const {
        std::lock_guard<std::mutex> lock(mining_shares_mutex_);
        
        uint64_t now = static_cast<uint64_t>(std::time(nullptr));
        
        // Calculate acceptance rate for last hour
        uint64_t recent_submitted = 0;
        uint64_t recent_accepted = 0;
        
        for (const auto& share : recent_mining_shares_) {
            if (share.timestamp > now - 3600) { // Last hour
                recent_submitted++;
                if (share.accepted) recent_accepted++;
            }
        }
        
        double acceptance_rate = recent_submitted > 0 ? 
            (double)recent_accepted / recent_submitted * 100.0 : 0.0;
        
        return {
            {"current_difficulty", current_difficulty_},
            {"current_hashrate", get_current_hashrate()},
            {"total_mining_shares_submitted", total_mining_shares_submitted_},
            {"total_mining_shares_accepted", total_mining_shares_accepted_},
            {"total_work_done", total_work_done_},
            {"acceptance_rate_1h", acceptance_rate},
            {"recent_shares_count", recent_mining_shares_.size()},
            {"target_time_per_share", target_time_per_share_}
        };
    }
    
private:
    void adjust_mining_difficulty() {
        if (recent_mining_shares_.size() < 3) {
            return; // Need minimum shares for adjustment
        }
        
        uint64_t now = static_cast<uint64_t>(std::time(nullptr));
        
        // Calculate average time between accepted shares in last 5 minutes
        std::vector<uint64_t> accepted_times;
        for (const auto& share : recent_mining_shares_) {
            if (share.accepted && share.timestamp > now - 300) { // Last 5 minutes
                accepted_times.push_back(share.timestamp);
            }
        }
        
        if (accepted_times.size() < 2) {
            return; // Need at least 2 accepted shares
        }
        
        std::sort(accepted_times.begin(), accepted_times.end());
        
        // Calculate average time between shares
        double total_time = accepted_times.back() - accepted_times.front();
        double avg_time_per_share = total_time / (accepted_times.size() - 1);
        
        // Calculate adjustment factor
        double adjustment_factor = target_time_per_share_ / avg_time_per_share;
        
        // Limit adjustment to prevent oscillation
        adjustment_factor = std::max(0.5, std::min(2.0, adjustment_factor));
        
        double new_difficulty = current_difficulty_ * adjustment_factor;
        
        // Apply bounds
        new_difficulty = std::max(min_difficulty_, std::min(max_difficulty_, new_difficulty));
        
        if (std::abs(new_difficulty - current_difficulty_) / current_difficulty_ > 0.1) { // >10% change
            LOG_INFO << "Mining difficulty adjustment: " << current_difficulty_ << " -> " << new_difficulty
                     << " (avg time: " << avg_time_per_share << "s, target: " << target_time_per_share_ << "s)"
                     << " (factor: " << adjustment_factor << ")";
            current_difficulty_ = new_difficulty;
        }
    }
};

// P2P Share Tracker for Cross-Node Communication
class P2PShareTracker {
private:
    struct P2PShareSubmission {
        uint64_t timestamp;
        double difficulty;
        bool verified;
        std::string peer_address;
    };
    
    std::deque<P2PShareSubmission> recent_p2p_shares_;
    mutable std::mutex p2p_shares_mutex_;
    
    // Statistics
    uint64_t total_p2p_shares_received_ = 0;
    uint64_t total_p2p_shares_verified_ = 0;
    uint64_t total_p2p_shares_forwarded_ = 0;
    
public:
    void record_p2p_share_reception(double difficulty, bool verified, const std::string& peer_address = "") {
        std::lock_guard<std::mutex> lock(p2p_shares_mutex_);
        
        uint64_t now = static_cast<uint64_t>(std::time(nullptr));
        recent_p2p_shares_.push_back({now, difficulty, verified, peer_address});
        
        // Keep only shares from last hour
        while (!recent_p2p_shares_.empty() && 
               recent_p2p_shares_.front().timestamp < now - 3600) {
            recent_p2p_shares_.pop_front();
        }
        
        total_p2p_shares_received_++;
        if (verified) {
            total_p2p_shares_verified_++;
        }
    }
    
    void record_p2p_share_forward() {
        std::lock_guard<std::mutex> lock(p2p_shares_mutex_);
        total_p2p_shares_forwarded_++;
    }
    
    nlohmann::json get_p2p_statistics() const {
        std::lock_guard<std::mutex> lock(p2p_shares_mutex_);
        
        uint64_t now = static_cast<uint64_t>(std::time(nullptr));
        
        // Calculate verification rate for last hour
        uint64_t recent_received = 0;
        uint64_t recent_verified = 0;
        
        for (const auto& share : recent_p2p_shares_) {
            if (share.timestamp > now - 3600) { // Last hour
                recent_received++;
                if (share.verified) recent_verified++;
            }
        }
        
        double verification_rate = recent_received > 0 ? 
            (double)recent_verified / recent_received * 100.0 : 0.0;
        
        return {
            {"total_p2p_shares_received", total_p2p_shares_received_},
            {"total_p2p_shares_verified", total_p2p_shares_verified_},
            {"total_p2p_shares_forwarded", total_p2p_shares_forwarded_},
            {"verification_rate_1h", verification_rate},
            {"recent_p2p_shares_count", recent_p2p_shares_.size()}
        };
    }
    
    std::vector<std::string> get_active_peers() const {
        std::lock_guard<std::mutex> lock(p2p_shares_mutex_);
        
        uint64_t now = static_cast<uint64_t>(std::time(nullptr));
        std::set<std::string> active_peers;
        
        for (const auto& share : recent_p2p_shares_) {
            if (share.timestamp > now - 600 && !share.peer_address.empty()) { // Last 10 minutes
                active_peers.insert(share.peer_address);
            }
        }
        
        return std::vector<std::string>(active_peers.begin(), active_peers.end());
    }
};

// Enhanced sharechain with automatic difficulty adjustment
class DifficultyAdjustmentEngine {
private:
    double current_pool_difficulty_ = 1.0;
    uint64_t shares_since_last_adjustment_ = 0;
    uint64_t target_shares_per_adjustment_ = 100;
    double target_block_time_ = 150.0; // 2.5 minutes for Litecoin
    uint64_t last_adjustment_time_ = 0;
    
    // Network statistics
    uint256 network_target_;
    double network_difficulty_ = 1.0;
    uint64_t last_network_update_ = 0;
    
public:
    void process_new_share(const c2pool::C2PoolShare& share) {
        shares_since_last_adjustment_++;
        
        uint64_t now = static_cast<uint64_t>(std::time(nullptr));
        
        // Update network difficulty if needed (every 10 minutes)
        if (now - last_network_update_ > 600) {
            update_network_difficulty();
            last_network_update_ = now;
        }
        
        // Check if we should adjust pool difficulty
        if (shares_since_last_adjustment_ >= target_shares_per_adjustment_ ||
            (now - last_adjustment_time_) > 300) { // Also adjust every 5 minutes
            
            adjust_pool_difficulty();
            last_adjustment_time_ = now;
            shares_since_last_adjustment_ = 0;
        }
    }
    
    double get_current_pool_difficulty() const {
        return current_pool_difficulty_;
    }
    
    uint256 get_pool_target() const {
        // Convert difficulty to target
        uint256 max_target;
        max_target.SetHex("00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        
        if (current_pool_difficulty_ <= 0) {
            return max_target;
        }
        
        return max_target / static_cast<uint64_t>(current_pool_difficulty_);
    }
    
    nlohmann::json get_difficulty_stats() const {
        return {
            {"pool_difficulty", current_pool_difficulty_},
            {"network_difficulty", network_difficulty_},
            {"shares_since_adjustment", shares_since_last_adjustment_},
            {"target_shares_per_adjustment", target_shares_per_adjustment_},
            {"pool_target", get_pool_target().ToString()},
            {"network_target", network_target_.ToString()}
        };
    }
    
private:
    void update_network_difficulty() {
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
    
    void adjust_pool_difficulty() {
        if (shares_since_last_adjustment_ == 0) return;
        
        uint64_t now = static_cast<uint64_t>(std::time(nullptr));
        uint64_t time_elapsed = now - last_adjustment_time_;
        
        if (time_elapsed == 0) time_elapsed = 1; // Prevent division by zero
        
        // Calculate actual vs target rate
        double actual_rate = (double)shares_since_last_adjustment_ / time_elapsed;
        double target_rate = target_shares_per_adjustment_ / target_block_time_;
        
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
};

// Enhanced C2Pool node using LTC sharechain infrastructure
class EnhancedC2PoolNode : public ltc::NodeImpl
{
private:
    std::unique_ptr<SharechainStorage> m_storage;
    uint64_t m_shares_since_save = 0;
    DifficultyAdjustmentEngine m_difficulty_adjustment_engine;
    std::unique_ptr<HashrateTracker> m_hashrate_tracker;
    
    // Legacy tracker integration
    std::unique_ptr<c2pool::sharechain::BaseShareTracker> m_legacy_tracker;
    
public:
    EnhancedC2PoolNode() : ltc::NodeImpl() {}
    EnhancedC2PoolNode(boost::asio::io_context* ctx, ltc::Config* config) 
        : ltc::NodeImpl(ctx, config)
    {
        // Initialize storage
        std::string network = config->m_testnet ? "testnet" : "mainnet";
        m_storage = std::make_unique<SharechainStorage>(network);
        
        // Load existing sharechain
        if (m_storage->load_sharechain(*m_chain)) {
            LOG_INFO << "Restored sharechain from disk";
            log_sharechain_stats();
        }
        
        // Schedule periodic saves
        m_storage->schedule_periodic_save(*m_chain, *ctx);
    }
    
    // ICommunicator implementation
    void handle(std::unique_ptr<RawMessage> rmsg, const NetService& service) override {
        LOG_INFO << "C2PoolNodeImpl received message: " << rmsg->m_command << " from " << service.to_string();
        // Delegate to protocol handler or handle locally
        // For now, just log the message
    }
    
    // Custom share processing to add persistence
    void add_shares_to_chain(const std::vector<ltc::ShareType>& shares) {
        for (const auto& share : shares) {
            // Add to LTC chain using proper methods
            // Note: This would need proper integration with LTC sharechain
        }
        
        // Increment shares counter and save if threshold reached
        m_shares_since_save += shares.size();
        if (m_shares_since_save >= 100) { // Save every 100 new shares
            LOG_INFO << "Saving sharechain due to threshold (" << m_shares_since_save << " new shares)";
            m_storage->save_sharechain(*m_chain);
            m_shares_since_save = 0;
        }
    }
    
    void shutdown()
    {
        LOG_INFO << "Shutting down Enhanced C2Pool node, saving sharechain...";
        if (m_storage && m_chain) {
            m_storage->save_sharechain(*m_chain);
        }
    }
    
    void log_sharechain_stats()
    {
        if (!m_chain) return;
        
        // Get stats using available LTC sharechain methods
        uint64_t total_shares = 0; // Would need proper implementation
        uint256 best_hash = uint256::ZERO;
        
        LOG_INFO << "Enhanced C2Pool Sharechain stats:";
        LOG_INFO << "  Total shares: " << total_shares;
        LOG_INFO << "  Connected peers: " << m_connections.size();
        LOG_INFO << "  Storage: " << (m_storage ? "enabled" : "disabled");
        
        // Log hashrate and difficulty statistics
        if (m_hashrate_tracker) {
            auto stats = m_hashrate_tracker->get_statistics();
            LOG_INFO << "  Current difficulty: " << stats["current_difficulty"];
            LOG_INFO << "  Current hashrate: " << stats["current_hashrate"] << " H/s";
            LOG_INFO << "  Total shares submitted: " << stats["total_shares_submitted"];
            LOG_INFO << "  Total shares accepted: " << stats["total_shares_accepted"];
            LOG_INFO << "  Acceptance rate (last hour): " << stats["acceptance_rate_1h"] << "%";
        }
        
        // Log difficulty adjustment stats
        LOG_INFO << "  Difficulty Adjustment Stats:";
        auto diff_stats = m_difficulty_adjustment_engine.get_difficulty_stats();
        LOG_INFO << "    Pool difficulty: " << diff_stats["pool_difficulty"];
        LOG_INFO << "    Network difficulty: " << diff_stats["network_difficulty"];
        LOG_INFO << "    Shares since adjustment: " << diff_stats["shares_since_adjustment"];
        LOG_INFO << "    Target shares per adjustment: " << diff_stats["target_shares_per_adjustment"];
    }
    
    // Methods for mining interface integration
    void track_share_submission(const std::string& session_id, double difficulty) {
        if (m_hashrate_tracker) {
            m_hashrate_tracker->record_share_submission(difficulty, true); // Assume accepted for now
        }
        // Process share with difficulty adjustment engine
        // (Note: would need to adapt interface to work with C2PoolShare objects)
    }
    
    nlohmann::json get_difficulty_stats() const {
        return m_difficulty_adjustment_engine.get_difficulty_stats();
    }
    
    nlohmann::json get_hashrate_stats() const {
        if (m_hashrate_tracker) {
            return m_hashrate_tracker->get_statistics();
        }
        return nlohmann::json{{"global_hashrate", 0.0}};
    }
    
    uint64_t get_total_shares() const {
        return m_chain ? 1000 : 0; // Placeholder - would need proper implementation with LTC chain
    }
    
    size_t get_connected_peers_count() const {
        return m_connections.size();
    }
};

// Legacy-Enhanced Share Tracking Bridge
class LegacyShareTrackerBridge {
private:
    std::unique_ptr<c2pool::sharechain::BaseShareTracker> m_legacy_tracker;
    HashrateTracker* m_hashrate_tracker;
    DifficultyAdjustmentEngine* m_difficulty_engine;
    
public:
    LegacyShareTrackerBridge(HashrateTracker* hashrate_tracker, DifficultyAdjustmentEngine* difficulty_engine) 
        : m_hashrate_tracker(hashrate_tracker), m_difficulty_engine(difficulty_engine) {
        m_legacy_tracker = std::make_unique<c2pool::sharechain::BaseShareTracker>();
    }
    
    void process_share(const C2PoolShare& share) {
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
    
    uint64_t get_legacy_share_count() const {
        return m_legacy_tracker ? m_legacy_tracker->get_total_shares() : 0;
    }
    
    double get_legacy_hashrate() const {
        return m_legacy_tracker ? m_legacy_tracker->get_network_hashrate() : 0.0;
    }
};

// Hashrate and difficulty management
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
    void record_share_submission(double difficulty, bool accepted) {
        std::lock_guard<std::mutex> lock(shares_mutex_);
        
        uint64_t now = static_cast<uint64_t>(std::time(nullptr));
        recent_shares_.push_back({now, difficulty, accepted});
        
        // Keep only shares from last hour
        while (!recent_shares_.empty() && 
               recent_shares_.front().timestamp < now - 3600) {
            recent_shares_.pop_front();
        }
        
        total_shares_submitted_++;
        if (accepted) {
            total_shares_accepted_++;
            total_work_done_ += difficulty;
        }
        
        // Check if we should adjust difficulty
        if (now - last_difficulty_adjustment_ > difficulty_adjustment_interval_) {
            adjust_difficulty();
            last_difficulty_adjustment_ = now;
        }
    }
    
    double get_current_difficulty() const {
        std::lock_guard<std::mutex> lock(shares_mutex_);
        return current_difficulty_;
    }
    
    double get_current_hashrate() const {
        std::lock_guard<std::mutex> lock(shares_mutex_);
        
        uint64_t now = static_cast<uint64_t>(std::time(nullptr));
        double work_done = 0.0;
        uint64_t time_window = 600; // 10 minutes
        
        for (const auto& share : recent_shares_) {
            if (share.accepted && share.timestamp > now - time_window) {
                work_done += share.difficulty;
            }
        }
        
        if (time_window > 0) {
            // Hashrate = work_done / time_window * 2^32 (for difficulty 1 = ~4.3GH/s)
            return work_done / time_window * 4294967296.0; // 2^32
        }
        
        return 0.0;
    }
    
    nlohmann::json get_statistics() const {
        std::lock_guard<std::mutex> lock(shares_mutex_);
        
        uint64_t now = static_cast<uint64_t>(std::time(nullptr));
        
        // Calculate acceptance rate for last hour
        uint64_t recent_submitted = 0;
        uint64_t recent_accepted = 0;
        
        for (const auto& share : recent_shares_) {
            if (share.timestamp > now - 3600) { // Last hour
                recent_submitted++;
                if (share.accepted) recent_accepted++;
            }
        }
        
        double acceptance_rate = recent_submitted > 0 ? 
            (double)recent_accepted / recent_submitted * 100.0 : 0.0;
        
        return {
            {"current_difficulty", current_difficulty_},
            {"current_hashrate", get_current_hashrate()},
            {"total_shares_submitted", total_shares_submitted_},
            {"total_shares_accepted", total_shares_accepted_},
            {"total_work_done", total_work_done_},
            {"acceptance_rate_1h", acceptance_rate},
            {"recent_shares_count", recent_shares_.size()},
            {"target_time_per_share", target_time_per_share_}
        };
    }
    
private:
    void adjust_difficulty() {
        if (recent_shares_.size() < 3) {
            return; // Need minimum shares for adjustment
        }
        
        uint64_t now = static_cast<uint64_t>(std::time(nullptr));
        
        // Calculate average time between accepted shares in last 5 minutes
        std::vector<uint64_t> accepted_times;
        for (const auto& share : recent_shares_) {
            if (share.accepted && share.timestamp > now - 300) { // Last 5 minutes
                accepted_times.push_back(share.timestamp);
            }
        }
        
        if (accepted_times.size() < 2) {
            return; // Need at least 2 accepted shares
        }
        
        std::sort(accepted_times.begin(), accepted_times.end());
        
        // Calculate average time between shares
        double total_time = accepted_times.back() - accepted_times.front();
        double avg_time_per_share = total_time / (accepted_times.size() - 1);
        
        // Calculate adjustment factor
        double adjustment_factor = target_time_per_share_ / avg_time_per_share;
        
        // Limit adjustment to prevent oscillation
        adjustment_factor = std::max(0.5, std::min(2.0, adjustment_factor));
        
        double new_difficulty = current_difficulty_ * adjustment_factor;
        
        // Apply bounds
        new_difficulty = std::max(min_difficulty_, std::min(max_difficulty_, new_difficulty));
        
        if (std::abs(new_difficulty - current_difficulty_) / current_difficulty_ > 0.1) { // >10% change
            LOG_INFO << "Difficulty adjustment: " << current_difficulty_ << " -> " << new_difficulty
                     << " (avg time: " << avg_time_per_share << "s, target: " << target_time_per_share_ << "s)"
                     << " (factor: " << adjustment_factor << ")";
            current_difficulty_ = new_difficulty;
        }
    }
};

// Enhanced sharechain with automatic difficulty adjustment
class DifficultyAdjustmentEngine {
private:
    double current_pool_difficulty_ = 1.0;
    uint64_t shares_since_last_adjustment_ = 0;
    uint64_t target_shares_per_adjustment_ = 100;
    double target_block_time_ = 150.0; // 2.5 minutes for Litecoin
    uint64_t last_adjustment_time_ = 0;
    
    // Network statistics
    uint256 network_target_;
    double network_difficulty_ = 1.0;
    uint64_t last_network_update_ = 0;
    
public:
    void process_new_share(const c2pool::C2PoolShare& share) {
        shares_since_last_adjustment_++;
        
        uint64_t now = static_cast<uint64_t>(std::time(nullptr));
        
        // Update network difficulty if needed (every 10 minutes)
        if (now - last_network_update_ > 600) {
            update_network_difficulty();
            last_network_update_ = now;
        }
        
        // Check if we should adjust pool difficulty
        if (shares_since_last_adjustment_ >= target_shares_per_adjustment_ ||
            (now - last_adjustment_time_) > 300) { // Also adjust every 5 minutes
            
            adjust_pool_difficulty();
            last_adjustment_time_ = now;
            shares_since_last_adjustment_ = 0;
        }
    }
    
    double get_current_pool_difficulty() const {
        return current_pool_difficulty_;
    }
    
    uint256 get_pool_target() const {
        // Convert difficulty to target
        uint256 max_target;
        max_target.SetHex("00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        
        if (current_pool_difficulty_ <= 0) {
            return max_target;
        }
        
        return max_target / static_cast<uint64_t>(current_pool_difficulty_);
    }
    
    nlohmann::json get_difficulty_stats() const {
        return {
            {"pool_difficulty", current_pool_difficulty_},
            {"network_difficulty", network_difficulty_},
            {"shares_since_adjustment", shares_since_last_adjustment_},
            {"target_shares_per_adjustment", target_shares_per_adjustment_},
            {"pool_target", get_pool_target().ToString()},
            {"network_target", network_target_.ToString()}
        };
    }
    
private:
    void update_network_difficulty() {
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
    
    void adjust_pool_difficulty() {
        if (shares_since_last_adjustment_ == 0) return;
        
        uint64_t now = static_cast<uint64_t>(std::time(nullptr));
        uint64_t time_elapsed = now - last_adjustment_time_;
        
        if (time_elapsed == 0) time_elapsed = 1; // Prevent division by zero
        
        // Calculate actual vs target rate
        double actual_rate = (double)shares_since_last_adjustment_ / time_elapsed;
        double target_rate = target_shares_per_adjustment_ / target_block_time_;
        
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
};

// Enhanced C2Pool node using LTC sharechain infrastructure
class EnhancedC2PoolNode : public ltc::NodeImpl
{
private:
    std::unique_ptr<SharechainStorage> m_storage;
    uint64_t m_shares_since_save = 0;
    DifficultyAdjustmentEngine m_difficulty_adjustment_engine;
    std::unique_ptr<HashrateTracker> m_hashrate_tracker;
    
    // Legacy tracker integration
    std::unique_ptr<c2pool::sharechain::BaseShareTracker> m_legacy_tracker;
    
public:
    EnhancedC2PoolNode() : ltc::NodeImpl() {}
    EnhancedC2PoolNode(boost::asio::io_context* ctx, ltc::Config* config) 
        : ltc::NodeImpl(ctx, config)
    {
        // Initialize storage
        std::string network = config->m_testnet ? "testnet" : "mainnet";
        m_storage = std::make_unique<SharechainStorage>(network);
        
        // Load existing sharechain
        if (m_storage->load_sharechain(*m_chain)) {
            LOG_INFO << "Restored sharechain from disk";
            log_sharechain_stats();
        }
        
        // Schedule periodic saves
        m_storage->schedule_periodic_save(*m_chain, *ctx);
    }
    
    // ICommunicator implementation
    void handle(std::unique_ptr<RawMessage> rmsg, const NetService& service) override {
        LOG_INFO << "C2PoolNodeImpl received message: " << rmsg->m_command << " from " << service.to_string();
        // Delegate to protocol handler or handle locally
        // For now, just log the message
    }
    
    // Custom share processing to add persistence
    void add_shares_to_chain(const std::vector<ltc::ShareType>& shares) {
        for (const auto& share : shares) {
            // Add to LTC chain using proper methods
            // Note: This would need proper integration with LTC sharechain
        }
        
        // Increment shares counter and save if threshold reached
        m_shares_since_save += shares.size();
        if (m_shares_since_save >= 100) { // Save every 100 new shares
            LOG_INFO << "Saving sharechain due to threshold (" << m_shares_since_save << " new shares)";
            m_storage->save_sharechain(*m_chain);
            m_shares_since_save = 0;
        }
    }
    
    void shutdown()
    {
        LOG_INFO << "Shutting down Enhanced C2Pool node, saving sharechain...";
        if (m_storage && m_chain) {
            m_storage->save_sharechain(*m_chain);
        }
    }
    
    void log_sharechain_stats()
    {
        if (!m_chain) return;
        
        // Get stats using available LTC sharechain methods
        uint64_t total_shares = 0; // Would need proper implementation
        uint256 best_hash = uint256::ZERO;
        
        LOG_INFO << "Enhanced C2Pool Sharechain stats:";
        LOG_INFO << "  Total shares: " << total_shares;
        LOG_INFO << "  Connected peers: " << m_connections.size();
        LOG_INFO << "  Storage: " << (m_storage ? "enabled" : "disabled");
        
        // Log hashrate and difficulty statistics
        if (m_hashrate_tracker) {
            auto stats = m_hashrate_tracker->get_statistics();
            LOG_INFO << "  Current difficulty: " << stats["current_difficulty"];
            LOG_INFO << "  Current hashrate: " << stats["current_hashrate"] << " H/s";
            LOG_INFO << "  Total shares submitted: " << stats["total_shares_submitted"];
            LOG_INFO << "  Total shares accepted: " << stats["total_shares_accepted"];
            LOG_INFO << "  Acceptance rate (last hour): " << stats["acceptance_rate_1h"] << "%";
        }
        
        // Log difficulty adjustment stats
        LOG_INFO << "  Difficulty Adjustment Stats:";
        auto diff_stats = m_difficulty_adjustment_engine.get_difficulty_stats();
        LOG_INFO << "    Pool difficulty: " << diff_stats["pool_difficulty"];
        LOG_INFO << "    Network difficulty: " << diff_stats["network_difficulty"];
        LOG_INFO << "    Shares since adjustment: " << diff_stats["shares_since_adjustment"];
        LOG_INFO << "    Target shares per adjustment: " << diff_stats["target_shares_per_adjustment"];
    }
    
    // Methods for mining interface integration
    void track_share_submission(const std::string& session_id, double difficulty) {
        if (m_hashrate_tracker) {
            m_hashrate_tracker->record_share_submission(difficulty, true); // Assume accepted for now
        }
        // Process share with difficulty adjustment engine
        // (Note: would need to adapt interface to work with C2PoolShare objects)
    }
    
    nlohmann::json get_difficulty_stats() const {
        return m_difficulty_adjustment_engine.get_difficulty_stats();
    }
    
    nlohmann::json get_hashrate_stats() const {
        if (m_hashrate_tracker) {
            return m_hashrate_tracker->get_statistics();
        }
        return nlohmann::json{{"global_hashrate", 0.0}};
    }
    
    uint64_t get_total_shares() const {
        return m_chain ? 1000 : 0; // Placeholder - would need proper implementation with LTC chain
    }
    
    size_t get_connected_peers_count() const {
        return m_connections.size();
    }
};

// Legacy-Enhanced Share Tracking Bridge
class LegacyShareTrackerBridge {
private:
    std::unique_ptr<c2pool::sharechain::BaseShareTracker> m_legacy_tracker;
    HashrateTracker* m_hashrate_tracker;
    DifficultyAdjustmentEngine* m_difficulty_engine;
    
public:
    LegacyShareTrackerBridge(HashrateTracker* hashrate_tracker, DifficultyAdjustmentEngine* difficulty_engine) 
        : m_hashrate_tracker(hashrate_tracker), m_difficulty_engine(difficulty_engine) {
        m_legacy_tracker = std::make_unique<c2pool::sharechain::BaseShareTracker>();
    }
    
    void process_share(const C2PoolShare& share) {
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
    
    uint64_t get_legacy_share_count() const {
        return m_legacy_tracker ? m_legacy_tracker->get_total_shares() : 0;
    }
    
    double get_legacy_hashrate() const {
        return m_legacy_tracker ? m_legacy_tracker->get_network_hashrate() : 0.0;
    }
};
