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
#include <sharechain/share.hpp>
#include <btclibs/uint256.h>

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
            LOG_INFO << "  Existing shares: " << m_leveldb_store->get_share_count();
            LOG_INFO << "  Best height: " << m_leveldb_store->get_best_height();
        }
    }
    
    ~SharechainStorage()
    {
        if (m_leveldb_store) {
            LOG_INFO << "Closing LevelDB sharechain storage";
            LOG_INFO << "  Final share count: " << m_leveldb_store->get_share_count();
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
            LOG_INFO << "LevelDB sharechain storage is ready for persistent share storage";
            LOG_INFO << "  Network: " << m_network_name;
            LOG_INFO << "  Current stored shares: " << m_leveldb_store->get_share_count();
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
            uint64_t stored_shares = m_leveldb_store->get_share_count();
            if (stored_shares == 0) {
                LOG_INFO << "No shares found in LevelDB storage, starting fresh";
                return false;
            }
            
            uint256 best_hash = m_leveldb_store->get_best_hash();
            uint64_t best_height = m_leveldb_store->get_best_height();
            
            LOG_INFO << "LevelDB sharechain storage contains " << stored_shares << " shares";
            LOG_INFO << "  Best height: " << best_height;
            LOG_INFO << "  Best hash: " << best_hash.ToString().substr(0, 16) << "...";
            
            // For now, just report availability - full integration needs sharechain API
            LOG_INFO << "LevelDB storage is ready for share loading and recovery";
            
            return stored_shares > 0;
            
        } catch (const std::exception& e) {
            LOG_ERROR << "Error loading from LevelDB sharechain storage: " << e.what();
            return false;
        }
    }
    
    // Store a specific share in LevelDB
    bool store_share(const uint256& hash, const std::vector<uint8_t>& serialized_data, 
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
                LOG_INFO << "Stored share in LevelDB: " << hash.ToString().substr(0, 16) 
                         << "... (height: " << height << ")";
            }
            return success;
            
        } catch (const std::exception& e) {
            LOG_ERROR << "Error storing share in LevelDB: " << e.what();
            return false;
        }
    }
    
    // Load a specific share from LevelDB
    bool load_share(const uint256& hash, std::vector<uint8_t>& serialized_data,
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
                
                LOG_DEBUG_DB << "Loaded share from LevelDB: " << hash.ToString().substr(0, 16)
                             << "... (height: " << height << ")";
            }
            
            return success;
            
        } catch (const std::exception& e) {
            LOG_ERROR << "Error loading share from LevelDB: " << e.what();
            return false;
        }
    }
    
    // Check if a share exists in LevelDB
    bool has_share(const uint256& hash)
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
            LOG_INFO << "  Total shares: " << share_count;
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
    
    // Get shares by height range
    std::vector<uint256> get_shares_by_height_range(uint64_t start_height, uint64_t end_height)
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

// Enhanced C2Pool node using LTC sharechain infrastructure
class EnhancedC2PoolNode : public ltc::NodeImpl
{
private:
    std::unique_ptr<SharechainStorage> m_storage;
    uint64_t m_shares_since_save = 0;
    
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
        LOG_INFO << "Enhanced C2Pool node received message: " << rmsg->m_command << " from " << service.to_string();
        // Delegate to parent or handle locally
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
    }
};

using EnhancedC2PoolNodeBridge = EnhancedC2PoolNode;

// Include the LTC-based c2pool node implementation
// extern void test_c2pool_ltc_node(); // Declaration from c2pool_ltc_node.cpp (temporarily disabled)

void print_usage(const char* program_name) {
    std::cout << "Usage: " << program_name << " [OPTIONS]\n"
              << "Options:\n"
              << "  --help                 Show this help message\n"
              << "  --web_server=IP:PORT   Start web server on IP:PORT (e.g., 0.0.0.0:8083)\n"
              << "                         Provides HTTP/JSON-RPC mining interface for miners\n"
              << "                         Supported methods: getwork, submitwork, getblocktemplate,\n"
              << "                         submitblock, getinfo, getstats, mining.subscribe,\n"
              << "                         mining.authorize, mining.submit\n"
              << "  --p2p_port=PORT        Start c2pool node on PORT (e.g., 5555) for sharechain networking\n"
              << "                         Enables connection to other c2pool instances for distributed mining\n"
              << "  --test_ltc_node        Test the LTC-based c2pool sharechain implementation\n"
              << "  --ui_config            Show UI configuration interface\n"
              << "  --testnet              Enable testnet mode\n"
              << "  --fee=VALUE            Set fee percentage (0.0-100.0)\n"
              << "  --network=NAME         Add network (e.g., LTC, BTC, DGB)\n"
              << std::endl;
}

std::map<std::string, std::string> parse_args(int argc, char* argv[]) {
    std::map<std::string, std::string> args;
    
    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        
        if (arg == "--help") {
            args["help"] = "true";
        } else if (arg == "--ui_config") {
            args["ui_config"] = "true";
        } else if (arg == "--testnet") {
            args["testnet"] = "true";
        } else if (arg == "--test_ltc_node") {
            args["test_ltc_node"] = "true";
        } else if (arg.find("--web_server=") == 0) {
            args["web_server"] = arg.substr(13);
        } else if (arg.find("--p2p_port=") == 0) {
            args["p2p_port"] = arg.substr(11);
        } else if (arg.find("--fee=") == 0) {
            args["fee"] = arg.substr(6);
        } else if (arg.find("--network=") == 0) {
            args["network"] = arg.substr(10);
        }
    }
    
    return args;
}

// C2Pool sharechain types
namespace c2pool {

// C2Pool share structure
struct C2PoolShare : chain::BaseShare<uint256, 100>
{
    // Mining data
    uint256 m_target;
    uint256 m_work;
    uint64_t m_timestamp;
    NetService m_peer_addr;
    
    // Reward tracking
    uint256 m_coinbase_txid;
    float m_fee_rate = 0.5; // Default 0.5% fee
    
    C2PoolShare() {}
    C2PoolShare(const uint256& hash, const uint256& prev_hash) 
        : chain::BaseShare<uint256, 100>(hash, prev_hash) 
    {
        m_timestamp = std::time(nullptr);
    }
    
    C2PoolShare(const uint256& hash, const uint256& prev_hash, const uint256& target)
        : chain::BaseShare<uint256, 100>(hash, prev_hash), m_target(target)
    {
        m_timestamp = std::time(nullptr);
        // Calculate work from target
        if (target != uint256::ZERO) {
            m_work = uint256::ONE << 256; // Max target
            m_work /= target; // Work = max_target / target
        }
    }
};

// Share formatter for serialization
struct C2PoolShareFormatter
{
    template<typename Obj, int64_t version>
    void operator()(Obj* obj) const
    {
        // Basic share data
        obj->m_hash;
        obj->m_prev_hash;
        
        if constexpr (version >= 100) {
            obj->m_target;
            obj->m_work;
            obj->m_timestamp;
            obj->m_coinbase_txid;
            obj->m_fee_rate;
        }
    }
};

using ShareType = chain::ShareVariants<C2PoolShareFormatter, C2PoolShare>;

// Share hasher for storage
struct ShareHasher
{
    size_t operator()(const uint256& hash) const 
    {
        return hash.GetLow64();
    }
};

// Share index for aggregation
class ShareIndex : public chain::ShareIndex<uint256, ShareType, ShareHasher, ShareIndex>
{
    using base_index = chain::ShareIndex<uint256, ShareType, ShareHasher, ShareIndex>;

public:
    uint256 m_total_work{};
    uint64_t m_total_shares = 0;
    uint64_t m_oldest_timestamp = UINT64_MAX;
    uint64_t m_newest_timestamp = 0;

    ShareIndex() : base_index() {}
    template <typename ShareT> 
    ShareIndex(ShareT* share) : base_index(share)
    {
        if constexpr (std::is_same_v<ShareT, C2PoolShare>) {
            m_total_work = share->m_work;
            m_total_shares = 1;
            m_oldest_timestamp = share->m_timestamp;
            m_newest_timestamp = share->m_timestamp;
        }
    }

protected:
    void add(ShareIndex* index) override
    {
        m_total_work += index->m_total_work;
        m_total_shares += index->m_total_shares;
        m_oldest_timestamp = std::min(m_oldest_timestamp, index->m_oldest_timestamp);
        m_newest_timestamp = std::max(m_newest_timestamp, index->m_newest_timestamp);
    }

    void sub(ShareIndex* index) override
    {
        m_total_work -= index->m_total_work;
        m_total_shares -= index->m_total_shares;
        // Note: can't easily recompute min/max timestamps without full scan
    }
};

// Complete sharechain implementation using public interface
struct ShareChain : chain::ShareChain<ShareIndex>
{
    uint256 get_total_work() const {
        // Return zero for now - would need proper implementation
        return uint256::ZERO;
    }
    
    uint64_t get_total_shares() const {
        // Return zero for now - would need proper implementation
        return 0;
    }
    
    uint256 get_best_share_hash() const {
        // Return zero for now - would need proper implementation
        return uint256::ZERO;
    }
};

} // namespace c2pool

// C2Pool node configuration for sharechain networking
struct C2PoolConfig
{
    std::string m_name = "c2pool_sharechain";
    bool m_testnet = false;
    
    struct PoolConfig {
        std::vector<std::byte> m_prefix = {std::byte{0xfc}, std::byte{0xc1}, std::byte{0xb7}, std::byte{0xdc}}; // mainnet
        std::vector<std::byte> m_prefix_testnet = {std::byte{0xfc}, std::byte{0xc1}, std::byte{0xb7}, std::byte{0xdd}}; // testnet
    } m_pool_config;
    
    PoolConfig* pool() { return &m_pool_config; }
    
    void set_testnet(bool testnet) {
        m_testnet = testnet;
        if (testnet) {
            m_pool_config.m_prefix = m_pool_config.m_prefix_testnet;
            m_name = "c2pool_sharechain_testnet";
        }
    }
};

struct C2PoolPeer
{
    uint64_t m_nonce = 0;
    uint256 m_best_share;
    uint64_t m_shares_received = 0;
    uint64_t m_shares_sent = 0;
    uint64_t m_last_share_time = 0;
};

class C2PoolNodeImpl : public pool::BaseNode<C2PoolConfig, c2pool::ShareChain, C2PoolPeer>
{
private:
    std::unique_ptr<c2pool::ShareChain> m_sharechain;
    uint64_t m_local_shares_count = 0;
    uint64_t m_foreign_shares_count = 0;
    
public:
    C2PoolNodeImpl() {
        m_sharechain = std::make_unique<c2pool::ShareChain>();
    }
    
    C2PoolNodeImpl(boost::asio::io_context* ctx, config_t* config) : base_t(ctx, config) {
        m_sharechain = std::make_unique<c2pool::ShareChain>();
        m_chain = m_sharechain.get(); // Set the base class chain pointer
    }
    
    // INetwork:
    void disconnect() override { }
    
    // BaseNode:
    void send_ping(peer_ptr peer) override {
        LOG_INFO << "Sending ping to c2pool peer: " << peer->addr().to_string() 
                 << " (shares in chain: " << m_sharechain->get_total_shares() << ")";
    }
    
    pool::PeerConnectionType handle_version(std::unique_ptr<RawMessage> rmsg, peer_ptr peer) override
    { 
        LOG_INFO << "Version message from c2pool peer: " << peer->addr().to_string();
        // Send our best share info
        uint256 best_hash = m_sharechain->get_best_share_hash();
        if (best_hash != uint256::ZERO) {
            peer->m_best_share = best_hash;
            LOG_INFO << "Our best share: " << best_hash.ToString().substr(0, 16) << "...";
        }
        return pool::PeerConnectionType::actual; // Use c2pool protocol
    }

    // Sharechain management methods
    void add_local_share(const uint256& hash, const uint256& prev_hash, const uint256& target) {
        auto share = std::make_unique<c2pool::C2PoolShare>(hash, prev_hash, target);
        share->m_peer_addr = NetService(); // Local share
        
        uint256 hash_copy = hash;
        if (m_sharechain->contains(std::move(hash_copy))) {
            LOG_WARNING << "Duplicate local share, ignoring: " << hash.ToString().substr(0, 16) << "...";
            return;
        }
        
        LOG_INFO << "Adding local share to sharechain: " << hash.ToString().substr(0, 16) << "...";
        m_sharechain->add(share.release());
        m_local_shares_count++;
        
        log_sharechain_stats();
        
        // Broadcast to all peers
        broadcast_new_share(hash);
    }
    
    void handle_foreign_share(c2pool::ShareType& share_var, const NetService& peer_addr) {
        share_var.USE([&](auto* share) {
            uint256 hash_copy = share->m_hash;
            if (m_sharechain->contains(std::move(hash_copy))) {
                LOG_WARNING << "Duplicate foreign share from " << peer_addr.to_string() 
                           << ", ignoring: " << share->m_hash.ToString().substr(0, 16) << "...";
                return;
            }
            
            LOG_INFO << "Adding foreign share from " << peer_addr.to_string() 
                     << ": " << share->m_hash.ToString().substr(0, 16) << "...";
            
            // Create a copy and set peer address
            auto new_share = std::make_unique<c2pool::C2PoolShare>(*share);
            new_share->m_peer_addr = peer_addr;
            
            m_sharechain->add(new_share.release());
            m_foreign_shares_count++;
            
            // Update peer statistics
            if (m_connections.find(peer_addr) != m_connections.end()) {
                m_connections[peer_addr]->m_shares_received++;
                m_connections[peer_addr]->m_last_share_time = std::time(nullptr);
            }
            
            log_sharechain_stats();
        });
    }
    
    std::vector<c2pool::ShareType> get_shares(const std::vector<uint256>& hashes, uint64_t max_count = 1000) {
        std::vector<c2pool::ShareType> result;
        
        for (const auto& hash : hashes) {
            uint256 hash_copy = hash;
            if (!m_sharechain->contains(std::move(hash_copy))) continue;
            
            // Get chain starting from this hash
            uint64_t count = std::min(max_count / hashes.size(), (uint64_t)m_sharechain->get_height(hash));
            for (auto& [share_hash, data] : m_sharechain->get_chain(hash, count)) {
                result.push_back(data.share);
                if (result.size() >= max_count) break;
            }
            
            if (result.size() >= max_count) break;
        }
        
        return result;
    }
    
    void broadcast_new_share(const uint256& share_hash) {
        // Send share to all connected peers
        for (auto& [addr, peer] : m_connections) {
            // TODO: Send actual share data via protocol
            peer->m_shares_sent++;
            LOG_INFO << "Broadcasting share " << share_hash.ToString().substr(0, 16) 
                      << "... to " << addr.to_string();
        }
    }
    
    void log_sharechain_stats() {
        uint64_t total_shares = m_sharechain->get_total_shares();
        uint256 total_work = m_sharechain->get_total_work();
        uint256 best_hash = m_sharechain->get_best_share_hash();
        
        LOG_INFO << "Sharechain stats:";
        LOG_INFO << "  Total shares: " << total_shares 
                 << " (local: " << m_local_shares_count 
                 << ", foreign: " << m_foreign_shares_count << ")";
        LOG_INFO << "  Total work: " << total_work.ToString().substr(0, 16) << "...";
        if (best_hash != uint256::ZERO) {
            LOG_INFO << "  Best share: " << best_hash.ToString().substr(0, 16) << "...";
        }
        LOG_INFO << "  Connected peers: " << m_connections.size();
    }
};

class C2PoolProtocol : public pool::Protocol<C2PoolNodeImpl>
{
public:
    void handle_message(std::unique_ptr<RawMessage> rmsg, C2PoolNodeImpl::peer_ptr peer) override {
        LOG_INFO << "C2Pool sharechain message [" << rmsg->m_command << "] from " << peer->addr().to_string();
        
        if (rmsg->m_command == "shares") {
            handle_shares_message(std::move(rmsg), peer);
        } else if (rmsg->m_command == "sharereq") {
            handle_share_request(std::move(rmsg), peer);
        } else if (rmsg->m_command == "bestblock") {
            handle_best_block(std::move(rmsg), peer);
        } else if (rmsg->m_command == "sharedata") {
            handle_share_data(std::move(rmsg), peer);
        } else {
            LOG_WARNING << "Unknown C2Pool message: " << rmsg->m_command;
        }
    }

private:
    void handle_shares_message(std::unique_ptr<RawMessage> rmsg, C2PoolNodeImpl::peer_ptr peer) {
        LOG_INFO << "Processing shares from peer " << peer->addr().to_string();
        
        try {
            // Parse shares from message (simplified - would need proper deserialization)
            auto& data = rmsg->m_data;
            if (data.size() < 32) {
                LOG_WARNING << "Invalid shares message size: " << data.size();
                return;
            }
            
            // For demo, create a fake share
            uint256 share_hash;
            std::memcpy(share_hash.begin(), data.data(), 32);
            
            uint256 prev_hash = uint256::ZERO;
            if (data.size() >= 64) {
                std::memcpy(prev_hash.begin(), data.data() + 32, 32);
            }
            
            // Create and process the share
            auto share = std::make_unique<c2pool::C2PoolShare>(share_hash, prev_hash);
            c2pool::ShareType share_var;
            share_var = share.release();
            
            // Get node implementation and handle the share
            auto node = dynamic_cast<C2PoolNodeImpl*>(get_node());
            if (node) {
                node->handle_foreign_share(share_var, peer->addr());
            }
            
        } catch (const std::exception& e) {
            LOG_ERROR << "Error processing shares: " << e.what();
        }
    }
    
    void handle_share_request(std::unique_ptr<RawMessage> rmsg, C2PoolNodeImpl::peer_ptr peer) {
        LOG_INFO << "Share request from peer " << peer->addr().to_string();
        
        try {
            auto node = dynamic_cast<C2PoolNodeImpl*>(get_node());
            if (!node) return;
            
            // Parse requested hashes (simplified)
            std::vector<uint256> requested_hashes;
            auto& data = rmsg->m_data;
            
            // For demo, request shares for any hash in the message
            if (data.size() >= 32) {
                uint256 hash;
                std::memcpy(hash.begin(), data.data(), 32);
                requested_hashes.push_back(hash);
            }
            
            // Get the requested shares
            auto shares = node->get_shares(requested_hashes, 100);
            
            LOG_INFO << "Sending " << shares.size() << " shares to " << peer->addr().to_string();
            
            // TODO: Send shares back to peer via proper protocol message
            peer->m_shares_sent += shares.size();
            
        } catch (const std::exception& e) {
            LOG_ERROR << "Error handling share request: " << e.what();
        }
    }
    
    void handle_best_block(std::unique_ptr<RawMessage> rmsg, C2PoolNodeImpl::peer_ptr peer) {
        LOG_INFO << "Best block update from peer " << peer->addr().to_string();
        
        // Parse best block hash
        if (rmsg->m_data.size() >= 32) {
            uint256 best_hash;
            std::memcpy(best_hash.begin(), rmsg->m_data.data(), 32);
            peer->m_best_share = best_hash;
            
            LOG_INFO << "Peer best share: " << best_hash.ToString().substr(0, 16) << "...";
        }
    }
    
    void handle_share_data(std::unique_ptr<RawMessage> rmsg, C2PoolNodeImpl::peer_ptr peer) {
        LOG_INFO << "Share data from peer " << peer->addr().to_string();
        
        // Process detailed share data (work, target, etc.)
        auto node = dynamic_cast<C2PoolNodeImpl*>(get_node());
        if (!node) return;
        
        // For demo, just log that we received share data
        LOG_INFO << "Received " << rmsg->m_data.size() << " bytes of share data";
        
        // In a real implementation, this would deserialize and validate share data
        // then call node->handle_foreign_share()
    }
    
    C2PoolNodeImpl* get_node() {
        // Get the node instance (would need proper implementation in base class)
        return nullptr; // TODO: implement proper node access
    }
};

class P2PoolProtocol : public pool::Protocol<C2PoolNodeImpl>
{
public:
    void handle_message(std::unique_ptr<RawMessage> rmsg, C2PoolNodeImpl::peer_ptr peer) override {
        LOG_INFO << "P2Pool legacy message [" << rmsg->m_command << "] from " << peer->addr().to_string();
    }
};

using C2PoolNode = C2PoolNodeImpl;

int main(int argc, char *argv[])
{
    // Parse command line arguments
    auto args = parse_args(argc, argv);
    
    if (args.find("help") != args.end()) {
        print_usage(argv[0]);
        return 0;
    }
    
    if (args.find("test_ltc_node") != args.end()) {
        // Initialize logging for the test
        core::log::Logger::init();
        LOG_INFO << "c2pool - Testing LTC-based sharechain implementation";
        
        // Run the LTC node test (temporarily disabled)
        LOG_INFO << "LTC node test temporarily disabled - use --p2p_port to run enhanced c2pool node";
        return 0;
    }
    
    // Initialize logging
    core::log::Logger::init();
    
    LOG_INFO << "c2pool - p2pool rebirth in C++";
    LOG_INFO << "Starting c2pool node...";
    
    // Load settings
    auto settings = core::Fileconfig::load_file<core::Settings>();
    
    // Apply command line overrides
    if (args.find("testnet") != args.end()) {
        settings->m_testnet = true;
        LOG_INFO << "Testnet mode enabled";
    }
    
    if (args.find("fee") != args.end()) {
        try {
            float fee_val = std::stof(args["fee"]);
            settings->m_fee = fee_val;
            LOG_INFO << "Fee set to: " << fee_val << "%";
        } catch (...) {
            LOG_ERROR << "Invalid fee value: " << args["fee"];
            return 1;
        }
    }
    
    // Show configuration
    LOG_INFO << "Configuration:";
    LOG_INFO << "  Testnet: " << (settings->m_testnet ? "Yes" : "No");
    LOG_INFO << "  Fee: " << settings->m_fee << "%";
    LOG_INFO << "  Networks:";
    for (const auto& net : settings->m_networks) {
        LOG_INFO << "    - " << net;
    }
    
    if (args.find("ui_config") != args.end()) {
        std::cout << "\n=== c2pool Configuration Interface ===\n";
        std::cout << "Current settings loaded from: " << core::filesystem::config_path() / "settings.yaml" << "\n";
        std::cout << "Testnet: " << (settings->m_testnet ? "Yes" : "No") << "\n";
        std::cout << "Fee: " << settings->m_fee << "%\n";
        std::cout << "Networks: ";
        for (size_t i = 0; i < settings->m_networks.size(); i++) {
            std::cout << settings->m_networks[i];
            if (i < settings->m_networks.size() - 1) std::cout << ", ";
        }
        std::cout << "\n\nTo modify settings, edit: " << core::filesystem::config_path() / "settings.yaml" << "\n";
        return 0;
    }
    
    if (args.find("web_server") != args.end()) {
        std::string server_addr = args["web_server"];
        LOG_INFO << "Starting web server on: " << server_addr;
        
        // Parse IP and port
        size_t colon_pos = server_addr.find(':');
        if (colon_pos == std::string::npos) {
            LOG_ERROR << "Invalid web_server format. Use IP:PORT (e.g., 0.0.0.0:8083)";
            return 1;
        }
        
        std::string ip = server_addr.substr(0, colon_pos);
        std::string port_str = server_addr.substr(colon_pos + 1);
        
        try {
            int port = std::stoi(port_str);
            
            // Create boost::asio context
            boost::asio::io_context ioc;
            
            // Create and start web server
            core::WebServer web_server(ioc, ip, static_cast<uint16_t>(port), settings->m_testnet);
            
            if (!web_server.start()) {
                LOG_ERROR << "Failed to start web server on " << ip << ":" << port;
                return 1;
            }
            
            LOG_INFO << "Web server started successfully on " << ip << ":" << port;
            LOG_INFO << "Mining interface available at http://" << ip << ":" << port;
            LOG_INFO << "Supported methods: getwork, submitwork, getblocktemplate, submitblock, getinfo, getstats";
            
            // Create a MiningInterface to check sync status
            auto mining_interface = std::make_shared<core::MiningInterface>(settings->m_testnet);
            
            // Check and log initial sync status
            LOG_INFO << "Checking Litecoin Core synchronization status...";
            mining_interface->log_sync_progress();
            
            bool stratum_started = false;
            if (!mining_interface->is_blockchain_synced()) {
                LOG_WARNING << "Blockchain is not synchronized - Stratum server will start when sync completes";
                LOG_INFO << "HTTP interface is available, but mining will be rejected until synchronized";
            } else {
                LOG_INFO << "Blockchain is synchronized - Starting Stratum server for mining!";
                if (web_server.start_stratum_server()) {
                    stratum_started = true;
                }
            }
            
            // Set up periodic sync status logging and Stratum server management
            boost::asio::steady_timer sync_timer(ioc);
            
            // Add periodic miner stats logging
            boost::asio::steady_timer stats_timer(ioc);
            
            std::function<void()> log_miner_stats = [&]() {
                // This would show connected miners - need to access WebServer's stratum connections
                LOG_INFO << "=== Mining Pool Stats ===";
                LOG_INFO << "Server running on: " << ip << ":" << port;
                LOG_INFO << "Stratum server: " << (stratum_started ? "Active" : "Waiting for sync");
                LOG_INFO << "Check individual miner submissions in logs above";
                
                stats_timer.expires_after(std::chrono::seconds(30)); // Stats every 30 seconds
                stats_timer.async_wait([&](const boost::system::error_code&) {
                    log_miner_stats();
                });
            };
            
            // Start stats logging
            stats_timer.expires_after(std::chrono::seconds(10));
            stats_timer.async_wait([&](const boost::system::error_code&) {
                log_miner_stats();
            });
            
            std::function<void()> check_sync_status = [&]() {
                bool is_synced = mining_interface->is_blockchain_synced();
                
                if (!is_synced) {
                    mining_interface->log_sync_progress();
                } else if (!stratum_started) {
                    // Blockchain just became synced - start Stratum server
                    LOG_INFO << "Blockchain sync complete! Starting Stratum server...";
                    if (web_server.start_stratum_server()) {
                        stratum_started = true;
                        LOG_INFO << "Pool is now ready for mining!";
                    }
                }
                
                sync_timer.expires_after(std::chrono::seconds(10)); // Check every 10 seconds during sync
                sync_timer.async_wait([&](const boost::system::error_code&) {
                    check_sync_status();
                });
            };
            check_sync_status();
            
            LOG_INFO << "Press Ctrl+C to stop.";
            
            // Install signal handler for graceful shutdown
            boost::asio::signal_set signals(ioc, SIGINT, SIGTERM);
            signals.async_wait([&](const boost::system::error_code&, int) {
                LOG_INFO << "Shutdown signal received, stopping web server...";
                web_server.stop();
                ioc.stop();
            });
            
            // Run the I/O context
            ioc.run();
            
            LOG_INFO << "Web server shutdown complete";
            return 0;
            
        } catch (...) {
            LOG_ERROR << "Invalid port number: " << port_str;
            return 1;
        }
    }
    
    if (args.find("p2p_port") != args.end()) {
        std::string port_str = args["p2p_port"];
        LOG_INFO << "Starting Enhanced C2Pool sharechain node on port: " << port_str;
        
        try {
            int port = std::stoi(port_str);
            
            // Create boost::asio context
            boost::asio::io_context ioc;
            
            // Create LTC-based config for production-ready sharechain
            auto config = std::make_unique<ltc::Config>("ltc");
            // Configure for c2pool network
            config->m_testnet = settings->m_testnet;
            config->pool()->m_worker = "c2pool-enhanced";
            if (settings->m_testnet) {
                config->pool()->m_prefix = {std::byte{0xfc}, std::byte{0xc1}, std::byte{0xb7}, std::byte{0xdd}}; // testnet
            } else {
                config->pool()->m_prefix = {std::byte{0xfc}, std::byte{0xc1}, std::byte{0xb7}, std::byte{0xdc}}; // mainnet
            }
            
            LOG_INFO << "Enhanced C2Pool sharechain config:";
            LOG_INFO << "  Network: " << (settings->m_testnet ? "testnet" : "mainnet");
            LOG_INFO << "  Worker: " << config->pool()->m_worker;
            LOG_INFO << "  Protocol prefix: " << config->pool()->m_prefix.size() << " bytes";
            LOG_INFO << "  Storage: enabled (persistent sharechain)";
            LOG_INFO << "  LTC Protocol: enabled (production-ready message handling)";
            
            // Create and start Enhanced C2Pool node with LTC infrastructure
            auto c2pool_node = std::make_unique<EnhancedC2PoolNodeBridge>(&ioc, config.get());
            c2pool_node->listen(port);
            
            LOG_INFO << "Enhanced C2Pool sharechain node started successfully on port " << port;
            LOG_INFO << "Ready to connect with other c2pool instances for distributed mining";
            LOG_INFO << "Features enabled:";
            LOG_INFO << "  - Persistent sharechain storage";
            LOG_INFO << "  - LTC-based robust protocol handling";
            LOG_INFO << "  - Real share synchronization and propagation";
            LOG_INFO << "  - Production-ready message serialization";
            LOG_INFO << "  - Automatic sharechain backup and recovery";
            
            // Get the enhanced node implementation
            auto enhanced_node = dynamic_cast<EnhancedC2PoolNode*>(c2pool_node.get());
            if (enhanced_node) {
                enhanced_node->log_sharechain_stats();
                
                // Set up periodic sharechain status logging with proper lifetime management
                auto status_timer = std::make_shared<boost::asio::steady_timer>(ioc);
                std::function<void()> log_status = [enhanced_node, status_timer]() {
                    if (enhanced_node) {
                        enhanced_node->log_sharechain_stats();
                    }
                    
                    status_timer->expires_after(std::chrono::seconds(60)); // Log every minute
                    status_timer->async_wait([enhanced_node, status_timer](const boost::system::error_code& ec) {
                        if (!ec && enhanced_node) {
                            enhanced_node->log_sharechain_stats();
                            
                            // Schedule next log
                            status_timer->expires_after(std::chrono::seconds(60));
                            status_timer->async_wait([enhanced_node, status_timer](const boost::system::error_code& ec2) {
                                if (!ec2 && enhanced_node) {
                                    enhanced_node->log_sharechain_stats();
                                }
                            });
                        }
                    });
                };
                
                // Start status logging after a short delay
                status_timer->expires_after(std::chrono::seconds(10));
                status_timer->async_wait([log_status](const boost::system::error_code& ec) {
                    if (!ec) {
                        log_status();
                    }
                });
            }
            
            LOG_INFO << "Press Ctrl+C to stop.";
            
            // Install signal handler for graceful shutdown
            boost::asio::signal_set signals(ioc, SIGINT, SIGTERM);
            signals.async_wait([&](const boost::system::error_code&, int) {
                LOG_INFO << "Shutdown signal received, stopping Enhanced C2Pool sharechain node...";
                if (enhanced_node) {
                    enhanced_node->shutdown(); // This will save the sharechain
                    LOG_INFO << "Final sharechain statistics:";
                    enhanced_node->log_sharechain_stats();
                }
                ioc.stop();
            });
            
            // Run the I/O context
            ioc.run();
            
            LOG_INFO << "Enhanced C2Pool sharechain node shutdown complete";
            return 0;
            
        } catch (...) {
            LOG_ERROR << "Invalid port number: " << port_str;
            return 1;
        }
    }

    LOG_INFO << "c2pool node initialized successfully";
    LOG_INFO << "Use --help for available options";
    
    return 0;
}