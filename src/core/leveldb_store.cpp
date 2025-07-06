#include "leveldb_store.hpp"
#include <core/log.hpp>
#include <core/pack.hpp>
#include <leveldb/write_batch.h>
#include <leveldb/filter_policy.h>
#include <leveldb/cache.h>
#include <filesystem>
#include <sstream>

namespace core {

LevelDBStore::LevelDBStore(const std::string& db_path, const LevelDBOptions& options)
    : m_db_path(db_path), m_options(options), m_db(nullptr)
{
}

LevelDBStore::~LevelDBStore()
{
    close();
}

bool LevelDBStore::open()
{
    if (m_db) {
        LOG_WARNING << "LevelDB store already open at: " << m_db_path;
        return true;
    }

    try {
        // Create directory if it doesn't exist
        std::filesystem::create_directories(m_db_path);

        // Configure LevelDB options
        leveldb::Options db_options;
        db_options.create_if_missing = true;
        db_options.error_if_exists = false;
        db_options.paranoid_checks = m_options.paranoid_checks;
        db_options.write_buffer_size = m_options.write_buffer_size;
        db_options.max_open_files = m_options.max_open_files;
        db_options.block_size = m_options.block_size;
        db_options.compression = m_options.use_compression ? leveldb::kSnappyCompression : leveldb::kNoCompression;

        // Set up bloom filter for faster lookups
        if (m_options.bloom_filter_bits > 0) {
            db_options.filter_policy = leveldb::NewBloomFilterPolicy(m_options.bloom_filter_bits);
        }

        // Set up block cache
        if (m_options.block_cache_size > 0) {
            db_options.block_cache = leveldb::NewLRUCache(m_options.block_cache_size);
        }

        leveldb::DB* db_ptr;
        leveldb::Status status = leveldb::DB::Open(db_options, m_db_path, &db_ptr);
        
        if (!status.ok()) {
            LOG_ERROR << "Failed to open LevelDB at " << m_db_path << ": " << status.ToString();
            return false;
        }

        m_db.reset(db_ptr);
        LOG_INFO << "LevelDB store opened successfully at: " << m_db_path;
        return true;

    } catch (const std::exception& e) {
        LOG_ERROR << "Exception opening LevelDB: " << e.what();
        return false;
    }
}

void LevelDBStore::close()
{
    if (m_db) {
        LOG_INFO << "Closing LevelDB store at: " << m_db_path;
        m_db.reset();
    }
}

bool LevelDBStore::put(const std::string& key, const std::vector<uint8_t>& value)
{
    if (!m_db) {
        LOG_ERROR << "LevelDB store not open";
        return false;
    }

    leveldb::WriteOptions write_options;
    write_options.sync = m_options.sync_writes;

    leveldb::Slice key_slice(key);
    leveldb::Slice value_slice(reinterpret_cast<const char*>(value.data()), value.size());

    leveldb::Status status = m_db->Put(write_options, key_slice, value_slice);
    if (!status.ok()) {
        LOG_ERROR << "Failed to put key '" << key << "': " << status.ToString();
        return false;
    }

    return true;
}

bool LevelDBStore::get(const std::string& key, std::vector<uint8_t>& value)
{
    if (!m_db) {
        LOG_ERROR << "LevelDB store not open";
        return false;
    }

    leveldb::ReadOptions read_options;
    read_options.verify_checksums = m_options.verify_checksums;

    std::string raw_value;
    leveldb::Status status = m_db->Get(read_options, key, &raw_value);
    
    if (status.IsNotFound()) {
        return false;
    }
    
    if (!status.ok()) {
        LOG_ERROR << "Failed to get key '" << key << "': " << status.ToString();
        return false;
    }

    value.assign(raw_value.begin(), raw_value.end());
    return true;
}

bool LevelDBStore::remove(const std::string& key)
{
    if (!m_db) {
        LOG_ERROR << "LevelDB store not open";
        return false;
    }

    leveldb::WriteOptions write_options;
    write_options.sync = m_options.sync_writes;

    leveldb::Status status = m_db->Delete(write_options, key);
    if (!status.ok() && !status.IsNotFound()) {
        LOG_ERROR << "Failed to delete key '" << key << "': " << status.ToString();
        return false;
    }

    return true;
}

bool LevelDBStore::exists(const std::string& key)
{
    if (!m_db) {
        return false;
    }

    std::string value;
    leveldb::ReadOptions read_options;
    read_options.verify_checksums = false; // Skip checksum for existence check
    
    leveldb::Status status = m_db->Get(read_options, key, &value);
    return status.ok();
}

size_t LevelDBStore::count()
{
    if (!m_db) {
        return 0;
    }

    size_t count = 0;
    std::unique_ptr<leveldb::Iterator> it(m_db->NewIterator(leveldb::ReadOptions()));
    
    for (it->SeekToFirst(); it->Valid(); it->Next()) {
        count++;
    }
    
    if (!it->status().ok()) {
        LOG_ERROR << "Error counting records: " << it->status().ToString();
        return 0;
    }

    return count;
}

std::vector<std::string> LevelDBStore::list_keys(const std::string& prefix, size_t limit)
{
    std::vector<std::string> keys;
    if (!m_db) {
        return keys;
    }

    std::unique_ptr<leveldb::Iterator> it(m_db->NewIterator(leveldb::ReadOptions()));
    
    if (prefix.empty()) {
        it->SeekToFirst();
    } else {
        it->Seek(prefix);
    }

    while (it->Valid() && keys.size() < limit) {
        std::string key = it->key().ToString();
        
        // If we have a prefix, check if the key still matches
        if (!prefix.empty() && key.substr(0, prefix.length()) != prefix) {
            break;
        }
        
        keys.push_back(key);
        it->Next();
    }

    if (!it->status().ok()) {
        LOG_ERROR << "Error listing keys: " << it->status().ToString();
        keys.clear();
    }

    return keys;
}

void LevelDBStore::compact()
{
    if (!m_db) {
        LOG_ERROR << "LevelDB store not open";
        return;
    }

    LOG_INFO << "Starting LevelDB compaction...";
    m_db->CompactRange(nullptr, nullptr);
    LOG_INFO << "LevelDB compaction completed";
}

LevelDBStore::BatchWriter LevelDBStore::create_batch()
{
    return BatchWriter(this);
}

// BatchWriter implementation
LevelDBStore::BatchWriter::BatchWriter(LevelDBStore* store)
    : m_store(store), m_batch(std::make_unique<leveldb::WriteBatch>())
{
}

LevelDBStore::BatchWriter::~BatchWriter() = default;

void LevelDBStore::BatchWriter::put(const std::string& key, const std::vector<uint8_t>& value)
{
    leveldb::Slice key_slice(key);
    leveldb::Slice value_slice(reinterpret_cast<const char*>(value.data()), value.size());
    m_batch->Put(key_slice, value_slice);
}

void LevelDBStore::BatchWriter::remove(const std::string& key)
{
    m_batch->Delete(key);
}

bool LevelDBStore::BatchWriter::commit()
{
    if (!m_store || !m_store->m_db) {
        LOG_ERROR << "LevelDB store not available for batch commit";
        return false;
    }

    leveldb::WriteOptions write_options;
    write_options.sync = m_store->m_options.sync_writes;

    leveldb::Status status = m_store->m_db->Write(write_options, m_batch.get());
    if (!status.ok()) {
        LOG_ERROR << "Failed to commit batch: " << status.ToString();
        return false;
    }

    return true;
}

// SharechainLevelDBStore implementation
SharechainLevelDBStore::SharechainLevelDBStore(const std::string& base_path, const std::string& network_name)
    : m_base_path(base_path), m_network_name(network_name)
{
    m_db_path = std::filesystem::path(base_path) / network_name / "sharechain_leveldb";
    
    // Configure optimized options for sharechain data
    m_options.write_buffer_size = 64 * 1024 * 1024;  // 64MB write buffer
    m_options.max_open_files = 1000;
    m_options.block_size = 16 * 1024;  // 16KB blocks
    m_options.block_cache_size = 256 * 1024 * 1024;  // 256MB cache
    m_options.bloom_filter_bits = 10;  // Bloom filter for fast lookups
    m_options.use_compression = true;   // Enable compression
    m_options.sync_writes = false;      // Async writes for performance
    m_options.verify_checksums = true;
    m_options.paranoid_checks = false;
    
    m_store = std::make_unique<LevelDBStore>(m_db_path, m_options);
}

SharechainLevelDBStore::~SharechainLevelDBStore()
{
    close();
}

bool SharechainLevelDBStore::open()
{
    if (!m_store->open()) {
        return false;
    }

    // Load metadata
    load_metadata();
    
    LOG_INFO << "SharechainLevelDBStore opened for network: " << m_network_name;
    LOG_INFO << "  Database path: " << m_db_path;
    LOG_INFO << "  Stored shares: " << m_metadata.total_shares;
    LOG_INFO << "  Database version: " << m_metadata.version;
    
    return true;
}

void SharechainLevelDBStore::close()
{
    if (m_store) {
        save_metadata();
        m_store->close();
    }
}

std::string SharechainLevelDBStore::make_share_key(const uint256& hash) const
{
    return "share:" + hash.ToString();
}

std::string SharechainLevelDBStore::make_index_key(const uint256& hash) const
{
    return "index:" + hash.ToString();
}

std::string SharechainLevelDBStore::make_height_key(uint64_t height) const
{
    // Zero-pad height for proper lexicographic ordering
    std::ostringstream oss;
    oss << "height:" << std::setfill('0') << std::setw(16) << height;
    return oss.str();
}

bool SharechainLevelDBStore::store_share(const uint256& hash, const std::vector<uint8_t>& serialized_share, const ShareMetadata& metadata)
{
    if (!m_store) {
        LOG_ERROR << "SharechainLevelDBStore not open";
        return false;
    }

    try {
        auto batch = m_store->create_batch();
        
        // Store the share data
        std::string share_key = make_share_key(hash);
        batch.put(share_key, serialized_share);
        
        // Store share metadata (for indexing and quick lookups)
        std::string index_key = make_index_key(hash);
        PackStream metadata_stream;
        metadata_stream << metadata.prev_hash;
        metadata_stream << metadata.height;
        metadata_stream << metadata.timestamp;
        metadata_stream << metadata.work;
        metadata_stream << metadata.target;
        metadata_stream << static_cast<uint8_t>(metadata.is_orphan ? 1 : 0);
        
        // Convert from std::vector<std::byte> to std::vector<uint8_t>
        auto span = metadata_stream.get_span();
        std::vector<uint8_t> metadata_data(
            reinterpret_cast<const uint8_t*>(span.data()),
            reinterpret_cast<const uint8_t*>(span.data()) + span.size()
        );
        batch.put(index_key, metadata_data);
        
        // Store height -> hash mapping for chain traversal
        if (metadata.height > 0) {
            std::string height_key = make_height_key(metadata.height);
            std::vector<uint8_t> hash_data(hash.data(), hash.data() + 32);
            batch.put(height_key, hash_data);
        }
        
        if (!batch.commit()) {
            LOG_ERROR << "Failed to store share: " << hash.ToString();
            return false;
        }
        
        // Update in-memory metadata
        m_metadata.total_shares++;
        if (metadata.height > m_metadata.max_height) {
            m_metadata.max_height = metadata.height;
            m_metadata.best_hash = hash;
        }
        
        return true;
        
    } catch (const std::exception& e) {
        LOG_ERROR << "Exception storing share " << hash.ToString() << ": " << e.what();
        return false;
    }
}

bool SharechainLevelDBStore::load_share(const uint256& hash, std::vector<uint8_t>& serialized_share, ShareMetadata& metadata)
{
    if (!m_store) {
        LOG_ERROR << "SharechainLevelDBStore not open";
        return false;
    }

    try {
        // Load share data
        std::string share_key = make_share_key(hash);
        if (!m_store->get(share_key, serialized_share)) {
            return false; // Share not found
        }
        
        // Load metadata
        std::string index_key = make_index_key(hash);
        std::vector<uint8_t> metadata_data;
        if (!m_store->get(index_key, metadata_data)) {
            LOG_ERROR << "Share data found but metadata missing for: " << hash.ToString();
            return false;
        }
        
        // Convert metadata data to PackStream for deserialization
        PackStream metadata_stream(std::span<const std::byte>(
            reinterpret_cast<const std::byte*>(metadata_data.data()),
            metadata_data.size()
        ));
        metadata_stream >> metadata.prev_hash;
        metadata_stream >> metadata.height;
        metadata_stream >> metadata.timestamp;
        metadata_stream >> metadata.work;
        metadata_stream >> metadata.target;
        
        uint8_t orphan_flag;
        metadata_stream >> orphan_flag;
        metadata.is_orphan = (orphan_flag != 0);
        
        return true;
        
    } catch (const std::exception& e) {
        LOG_ERROR << "Exception loading share " << hash.ToString() << ": " << e.what();
        return false;
    }
}

bool SharechainLevelDBStore::has_share(const uint256& hash)
{
    if (!m_store) {
        return false;
    }
    
    std::string share_key = make_share_key(hash);
    return m_store->exists(share_key);
}

bool SharechainLevelDBStore::remove_share(const uint256& hash)
{
    if (!m_store) {
        LOG_ERROR << "SharechainLevelDBStore not open";
        return false;
    }

    try {
        // Load metadata first to update counters
        ShareMetadata metadata;
        std::vector<uint8_t> dummy_data;
        bool had_metadata = load_share(hash, dummy_data, metadata);
        
        auto batch = m_store->create_batch();
        
        // Remove share data and metadata
        batch.remove(make_share_key(hash));
        batch.remove(make_index_key(hash));
        
        // Remove height mapping if we have metadata
        if (had_metadata && metadata.height > 0) {
            batch.remove(make_height_key(metadata.height));
        }
        
        if (!batch.commit()) {
            LOG_ERROR << "Failed to remove share: " << hash.ToString();
            return false;
        }
        
        // Update counters
        if (m_metadata.total_shares > 0) {
            m_metadata.total_shares--;
        }
        
        return true;
        
    } catch (const std::exception& e) {
        LOG_ERROR << "Exception removing share " << hash.ToString() << ": " << e.what();
        return false;
    }
}

std::vector<uint256> SharechainLevelDBStore::get_chain_hashes(const uint256& start_hash, uint64_t max_count, bool forward)
{
    std::vector<uint256> hashes;
    if (!m_store || max_count == 0) {
        return hashes;
    }

    try {
        // Load starting share metadata
        ShareMetadata start_metadata;
        std::vector<uint8_t> dummy_data;
        if (!load_share(start_hash, dummy_data, start_metadata)) {
            LOG_WARNING << "Start hash not found: " << start_hash.ToString();
            return hashes;
        }
        
        hashes.push_back(start_hash);
        
        uint256 current_hash = start_hash;
        uint64_t current_height = start_metadata.height;
        
        for (uint64_t i = 1; i < max_count; i++) {
            if (forward) {
                // Move forward in chain (higher height)
                current_height++;
                std::string height_key = make_height_key(current_height);
                std::vector<uint8_t> hash_data;
                
                if (!m_store->get(height_key, hash_data) || hash_data.size() != 32) {
                    break; // No more shares in chain
                }
                
                std::vector<unsigned char> hash_char_data(hash_data.begin(), hash_data.end());
                current_hash = uint256(hash_char_data);
            } else {
                // Move backward in chain (follow prev_hash)
                ShareMetadata metadata;
                if (!load_share(current_hash, dummy_data, metadata)) {
                    break;
                }
                
                if (metadata.prev_hash == uint256::ZERO) {
                    break; // Reached genesis
                }
                
                current_hash = metadata.prev_hash;
            }
            
            hashes.push_back(current_hash);
        }
        
    } catch (const std::exception& e) {
        LOG_ERROR << "Exception getting chain hashes: " << e.what();
        hashes.clear();
    }

    return hashes;
}

uint64_t SharechainLevelDBStore::get_share_count()
{
    return m_metadata.total_shares;
}

uint256 SharechainLevelDBStore::get_best_hash()
{
    return m_metadata.best_hash;
}

uint64_t SharechainLevelDBStore::get_best_height()
{
    return m_metadata.max_height;
}

std::vector<uint256> SharechainLevelDBStore::get_shares_by_height_range(uint64_t start_height, uint64_t end_height)
{
    std::vector<uint256> hashes;
    if (!m_store || start_height > end_height) {
        return hashes;
    }

    try {
        for (uint64_t height = start_height; height <= end_height; height++) {
            std::string height_key = make_height_key(height);
            std::vector<uint8_t> hash_data;
            
            if (m_store->get(height_key, hash_data) && hash_data.size() == 32) {
                std::vector<unsigned char> hash_char_data(hash_data.begin(), hash_data.end());
                uint256 hash(hash_char_data);
                hashes.push_back(hash);
            }
        }
        
    } catch (const std::exception& e) {
        LOG_ERROR << "Exception getting shares by height range: " << e.what();
        hashes.clear();
    }

    return hashes;
}

void SharechainLevelDBStore::compact()
{
    if (m_store) {
        LOG_INFO << "Compacting sharechain database...";
        m_store->compact();
        LOG_INFO << "Sharechain database compaction completed";
    }
}

void SharechainLevelDBStore::load_metadata()
{
    if (!m_store) {
        return;
    }

    std::vector<uint8_t> metadata_data;
    if (m_store->get("metadata", metadata_data)) {
        try {
            // Convert metadata data to PackStream for deserialization
            PackStream stream(std::span<const std::byte>(
                reinterpret_cast<const std::byte*>(metadata_data.data()),
                metadata_data.size()
            ));
            stream >> m_metadata.version;
            stream >> m_metadata.total_shares;
            stream >> m_metadata.max_height;
            stream >> m_metadata.best_hash;
            stream >> m_metadata.created_timestamp;
            stream >> m_metadata.last_updated_timestamp;
            
            LOG_INFO << "Loaded sharechain metadata: version=" << m_metadata.version 
                     << ", shares=" << m_metadata.total_shares 
                     << ", height=" << m_metadata.max_height;
        } catch (const std::exception& e) {
            LOG_WARNING << "Failed to parse metadata, using defaults: " << e.what();
            m_metadata = ChainMetadata{}; // Reset to defaults
        }
    } else {
        // No metadata found, this is a new database
        m_metadata = ChainMetadata{};
        m_metadata.created_timestamp = std::time(nullptr);
        LOG_INFO << "No existing metadata found, initializing new sharechain database";
    }
}

void SharechainLevelDBStore::save_metadata()
{
    if (!m_store) {
        return;
    }

    try {
        m_metadata.last_updated_timestamp = std::time(nullptr);
        
        PackStream stream;
        stream << m_metadata.version;
        stream << m_metadata.total_shares;
        stream << m_metadata.max_height;
        stream << m_metadata.best_hash;
        stream << m_metadata.created_timestamp;
        stream << m_metadata.last_updated_timestamp;
        
        // Convert from std::vector<std::byte> to std::vector<uint8_t>
        auto span = stream.get_span();
        std::vector<uint8_t> metadata_data(
            reinterpret_cast<const uint8_t*>(span.data()),
            reinterpret_cast<const uint8_t*>(span.data()) + span.size()
        );
        m_store->put("metadata", metadata_data);
        
    } catch (const std::exception& e) {
        LOG_ERROR << "Failed to save metadata: " << e.what();
    }
}

} // namespace core
