#include "sharechain_storage.hpp"
#include <functional>
#include <impl/ltc/share.hpp>

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

template<typename ShareChainType>
void SharechainStorage::save_sharechain(const ShareChainType& chain)
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

template<typename ShareChainType>
bool SharechainStorage::load_sharechain(ShareChainType& chain)
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

template<typename ShareChainType>
void SharechainStorage::schedule_periodic_save(ShareChainType& chain, boost::asio::io_context& ioc, int interval_seconds)
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

// Explicit template instantiations for common types
template void SharechainStorage::save_sharechain<ltc::ShareChain>(const ltc::ShareChain& chain);
template bool SharechainStorage::load_sharechain<ltc::ShareChain>(ltc::ShareChain& chain);
template void SharechainStorage::schedule_periodic_save<ltc::ShareChain>(ltc::ShareChain& chain, boost::asio::io_context& ioc, int interval_seconds);

} // namespace storage
} // namespace c2pool
