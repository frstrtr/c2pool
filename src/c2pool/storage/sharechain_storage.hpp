#pragma once

#include <memory>
#include <string>
#include <vector>
#include <core/leveldb_store.hpp>
#include <core/uint256.hpp>
#include <core/filesystem.hpp>
#include <core/log.hpp>
#include <boost/asio.hpp>

namespace c2pool {
namespace storage {

/** * @brief Modern LevelDB-based sharechain storage manager
 *
 * Provides persistent storage for sharechain data with automatic
 * distinction between mining_shares (from physical miners) and
 * p2p_shares (from cross-node communication). Both types are stored
 * in the same chain but can be tracked separately for statistics.
 * maintenance, compaction, and recovery capabilities.
 */
class SharechainStorage {
private:
    std::unique_ptr<core::SharechainLevelDBStore> m_leveldb_store;
    std::string m_network_name;
    
public:
    /**
     * @brief Construct sharechain storage for a specific network
     * @param network_name Name of the network (mainnet/testnet)
     */
    explicit SharechainStorage(const std::string& network_name);
    
    /**
     * @brief Destructor with cleanup
     */
    ~SharechainStorage();
    
    /**
     * @brief Check if storage is available and ready
     * @return True if storage is operational
     */
    bool is_available() const;
    
    /**
     * @brief Save sharechain to persistent storage
     * @tparam ShareChainType Type of sharechain to save
     * @param chain The sharechain to save
     */
    template<typename ShareChainType>
    void save_sharechain(const ShareChainType& chain);
    
    /**
     * @brief Load sharechain from persistent storage
     * @tparam ShareChainType Type of sharechain to load into
     * @param chain The sharechain to load into
     * @return True if shares were loaded
     */
    template<typename ShareChainType>
    bool load_sharechain(ShareChainType& chain);
    
    /**
     * @brief Store a specific share in the database
     * @param hash Share hash
     * @param serialized_data Serialized share data
     * @param prev_hash Previous share hash
     * @param height Chain height
     * @param timestamp Share timestamp
     * @param work Cumulative work
     * @param target Share target
     * @param is_orphan Whether share is orphaned
     * @return True if successful
     */
    bool store_share(const uint256& hash, const std::vector<uint8_t>& serialized_data, 
                     const uint256& prev_hash, uint64_t height, uint64_t timestamp,
                     const uint256& work, const uint256& target, bool is_orphan = false);
    
    /**
     * @brief Load a specific share from the database
     * @param hash Share hash to load
     * @param serialized_data Output: serialized share data
     * @param prev_hash Output: previous share hash
     * @param height Output: chain height
     * @param timestamp Output: share timestamp
     * @param work Output: cumulative work
     * @param target Output: share target
     * @param is_orphan Output: whether share is orphaned
     * @return True if successful
     */
    bool load_share(const uint256& hash, std::vector<uint8_t>& serialized_data,
                    uint256& prev_hash, uint64_t& height, uint64_t& timestamp,
                    uint256& work, uint256& target, bool& is_orphan);
    
    /**
     * @brief Check if a share exists in storage
     * @param hash Share hash to check
     * @return True if share exists
     */
    bool has_share(const uint256& hash);
    
    /**
     * @brief Log storage statistics
     */
    void log_storage_stats();
    
    /**
     * @brief Compact the database for optimization
     */
    void compact();
    
    /**
     * @brief Get chain hashes for synchronization
     * @param start_hash Starting hash
     * @param max_count Maximum number of hashes to return
     * @param forward Direction to traverse
     * @return Vector of hashes
     */
    std::vector<uint256> get_chain_hashes(const uint256& start_hash, uint64_t max_count, bool forward = true);
    
    /**
     * @brief Get shares in a height range
     * @param start_height Starting height
     * @param end_height Ending height
     * @return Vector of share hashes
     */
    std::vector<uint256> get_shares_by_height_range(uint64_t start_height, uint64_t end_height);
    
    /**
     * @brief Schedule periodic maintenance tasks
     * @tparam ShareChainType Type of sharechain
     * @param chain Sharechain reference
     * @param ioc IO context for timers
     * @param interval_seconds Maintenance interval
     */
    template<typename ShareChainType>
    void schedule_periodic_save(ShareChainType& chain, boost::asio::io_context& ioc, int interval_seconds = 300);
};

} // namespace storage
} // namespace c2pool
