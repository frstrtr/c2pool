#pragma once

#include <memory>
#include <string>
#include <vector>
#include <cstdint>
#include <leveldb/db.h>
#include <leveldb/options.h>
#include <leveldb/write_batch.h>
#include <core/uint256.hpp>

namespace core {

/**
 * Configuration options for LevelDB
 */
struct LevelDBOptions {
    size_t write_buffer_size = 4 * 1024 * 1024;  // 4MB
    int max_open_files = 1000;
    size_t block_size = 4 * 1024;  // 4KB
    size_t block_cache_size = 8 * 1024 * 1024;  // 8MB
    int bloom_filter_bits = 10;
    bool use_compression = true;
    bool sync_writes = false;
    bool verify_checksums = true;
    bool paranoid_checks = false;
};

/**
 * LevelDB-based key-value store
 */
class LevelDBStore
{
private:
    std::string m_db_path;
    LevelDBOptions m_options;
    std::unique_ptr<leveldb::DB> m_db;

public:
    class BatchWriter {
    private:
        LevelDBStore* m_store;
        std::unique_ptr<leveldb::WriteBatch> m_batch;

    public:
        BatchWriter(LevelDBStore* store);
        ~BatchWriter();
        
        void put(const std::string& key, const std::vector<uint8_t>& value);
        void remove(const std::string& key);
        bool commit();
    };

    LevelDBStore(const std::string& db_path, const LevelDBOptions& options);
    ~LevelDBStore();
    
    LevelDBStore(const LevelDBStore&) = delete;
    LevelDBStore& operator=(const LevelDBStore&) = delete;

    bool open();
    void close();

    bool put(const std::string& key, const std::vector<uint8_t>& value);
    bool get(const std::string& key, std::vector<uint8_t>& value);
    bool remove(const std::string& key);
    bool exists(const std::string& key);

    size_t count();
    std::vector<std::string> list_keys(const std::string& prefix = "", size_t limit = 1000);
    void compact();

    BatchWriter create_batch();
};

/**
 * Share metadata for indexing and chain traversal
 */
struct ShareMetadata {
    uint256 prev_hash = uint256::ZERO;
    uint64_t height = 0;
    uint64_t timestamp = 0;
    uint256 work = uint256::ZERO;
    uint256 target = uint256::ZERO;
    bool is_orphan = false;
};

/**
 * Chain metadata for database state tracking
 */
struct ChainMetadata {
    uint32_t version = 1;
    uint64_t total_shares = 0;
    uint64_t max_height = 0;
    uint256 best_hash = uint256::ZERO;
    uint64_t created_timestamp = 0;
    uint64_t last_updated_timestamp = 0;
};

/**
 * Specialized LevelDB store for sharechain data with optimized indexing
 */
class SharechainLevelDBStore
{
private:
    std::string m_base_path;
    std::string m_network_name;
    std::string m_db_path;
    LevelDBOptions m_options;
    std::unique_ptr<LevelDBStore> m_store;
    ChainMetadata m_metadata;

    // Key generation helpers
    std::string make_share_key(const uint256& hash) const;
    std::string make_index_key(const uint256& hash) const;
    std::string make_height_key(uint64_t height) const;

    // Metadata management
    void load_metadata();
    void save_metadata();

public:
    SharechainLevelDBStore(const std::string& base_path, const std::string& network_name);
    ~SharechainLevelDBStore();

    SharechainLevelDBStore(const SharechainLevelDBStore&) = delete;
    SharechainLevelDBStore& operator=(const SharechainLevelDBStore&) = delete;

    bool open();
    void close();

    // Share operations
    bool store_share(const uint256& hash, const std::vector<uint8_t>& serialized_share, const ShareMetadata& metadata);
    bool load_share(const uint256& hash, std::vector<uint8_t>& serialized_share, ShareMetadata& metadata);
    bool has_share(const uint256& hash);
    bool remove_share(const uint256& hash);

    // Chain traversal
    std::vector<uint256> get_chain_hashes(const uint256& start_hash, uint64_t max_count, bool forward = true);
    std::vector<uint256> get_shares_by_height_range(uint64_t start_height, uint64_t end_height);

    // Statistics
    uint64_t get_share_count();
    uint256 get_best_hash();
    uint64_t get_best_height();
    std::string get_base_path() const { return m_base_path; }

    // Maintenance
    void compact();
};

} // namespace core
