#include "sharechain_storage.hpp"
#include <functional>

namespace c2pool {
namespace storage {

SharechainStorage::SharechainStorage(const std::string& network_name) 
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

SharechainStorage::~SharechainStorage()
{
    if (m_leveldb_store) {
        LOG_INFO << "Closing LevelDB sharechain storage";
        LOG_INFO << "  Final share count: " << m_leveldb_store->get_share_count();
        m_leveldb_store->close();
    }
}

bool SharechainStorage::is_available() const {
    return m_leveldb_store != nullptr;
}

bool SharechainStorage::store_share(const uint256& hash, const std::vector<uint8_t>& serialized_data,
                 const uint256& prev_hash, uint64_t height, uint64_t timestamp,
                 const uint256& work, const uint256& target, bool is_orphan)
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

bool SharechainStorage::store_shares_batch(const std::vector<ShareBatchEntry>& entries)
{
    if (!m_leveldb_store || entries.empty())
        return false;

    try {
        // Delegate to LevelDB store's batch method
        return m_leveldb_store->store_shares_batch(entries);
    } catch (const std::exception& e) {
        LOG_ERROR << "Error storing share batch (" << entries.size() << " shares): " << e.what();
        return false;
    }
}

bool SharechainStorage::load_share(const uint256& hash, std::vector<uint8_t>& serialized_data,
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

bool SharechainStorage::has_share(const uint256& hash)
{
    if (!m_leveldb_store) {
        return false;
    }

    return m_leveldb_store->has_share(hash);
}

bool SharechainStorage::remove_share(const uint256& hash)
{
    if (!m_leveldb_store) {
        return false;
    }

    return m_leveldb_store->remove_share(hash);
}

bool SharechainStorage::remove_shares_batch(const std::vector<uint256>& hashes)
{
    if (!m_leveldb_store || hashes.empty())
        return false;
    return m_leveldb_store->remove_shares_batch(hashes);
}

bool SharechainStorage::load_share(const uint256& hash, std::vector<uint8_t>& serialized_data,
                core::ShareMetadata& metadata)
{
    if (!m_leveldb_store)
        return false;
    try {
        return m_leveldb_store->load_share(hash, serialized_data, metadata);
    } catch (const std::exception& e) {
        LOG_ERROR << "Error loading share from LevelDB: " << e.what();
        return false;
    }
}

bool SharechainStorage::mark_shares_verified(const std::vector<uint256>& hashes)
{
    if (!m_leveldb_store || hashes.empty())
        return false;
    return m_leveldb_store->mark_shares_verified(hashes);
}

bool SharechainStorage::mark_shares_verified_with_pow(
    const std::vector<std::pair<uint256, uint256>>& hash_pow_pairs)
{
    if (!m_leveldb_store || hash_pow_pairs.empty())
        return false;
    return m_leveldb_store->mark_shares_verified_with_pow(hash_pow_pairs);
}

void SharechainStorage::log_storage_stats()
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

void SharechainStorage::compact()
{
    if (m_leveldb_store) {
        LOG_INFO << "Compacting LevelDB sharechain storage...";
        m_leveldb_store->compact();
    }
}

std::vector<uint256> SharechainStorage::get_chain_hashes(const uint256& start_hash, uint64_t max_count, bool forward)
{
    if (!m_leveldb_store) {
        return {};
    }
    
    return m_leveldb_store->get_chain_hashes(start_hash, max_count, forward);
}

std::vector<uint256> SharechainStorage::get_shares_by_height_range(uint64_t start_height, uint64_t end_height)
{
    if (!m_leveldb_store) {
        return {};
    }
    
    return m_leveldb_store->get_shares_by_height_range(start_height, end_height);
}

// Template method bodies (save_sharechain, load_sharechain, schedule_periodic_save)
// live in the header so any coin's ShareChain type gets implicit instantiation.

} // namespace storage
} // namespace c2pool
