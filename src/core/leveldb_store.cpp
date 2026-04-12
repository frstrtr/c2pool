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

        // Recovery after unclean shutdown (crash, kill -9, power loss).
        // LevelDB uses fcntl locks on Linux which are released on process
        // death, but a stale LOCK file can remain and block reopening if
        // a zombie child still holds the fd or the OS didn't clean up.
        // Standard approach (same as Bitcoin Core / litecoind):
        //   1. Remove stale LOCK file → retry Open
        //   2. If still fails (corruption) → RepairDB → retry Open
        if (!status.ok()) {
            auto lock_path = std::filesystem::path(m_db_path) / "LOCK";
            if (std::filesystem::exists(lock_path)) {
                LOG_WARNING << "LevelDB open failed at " << m_db_path
                            << ": " << status.ToString()
                            << " — removing stale LOCK file and retrying";
                std::error_code ec;
                std::filesystem::remove(lock_path, ec);
                status = leveldb::DB::Open(db_options, m_db_path, &db_ptr);
            }
        }

        if (!status.ok()) {
            LOG_WARNING << "LevelDB open failed after LOCK removal at " << m_db_path
                        << ": " << status.ToString()
                        << " — attempting RepairDB (data will be preserved)";
            leveldb::Status repair = leveldb::RepairDB(m_db_path, db_options);
            if (repair.ok()) {
                LOG_INFO << "LevelDB RepairDB succeeded at " << m_db_path;
                status = leveldb::DB::Open(db_options, m_db_path, &db_ptr);
            } else {
                LOG_ERROR << "LevelDB RepairDB failed at " << m_db_path
                          << ": " << repair.ToString();
            }
        }

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

bool LevelDBStore::BatchWriter::commit_sync()
{
    if (!m_store || !m_store->m_db) {
        LOG_ERROR << "LevelDB store not available for batch commit_sync";
        return false;
    }

    leveldb::WriteOptions write_options;
    write_options.sync = true;  // force fsync

    leveldb::Status status = m_store->m_db->Write(write_options, m_batch.get());
    if (!status.ok()) {
        LOG_ERROR << "Failed to commit_sync batch: " << status.ToString();
        return false;
    }

    return true;
}

// SharechainLevelDBStore implementation
SharechainLevelDBStore::SharechainLevelDBStore(const std::string& base_path, const std::string& network_name)
    : m_base_path(base_path), m_network_name(network_name)
{
    m_db_path = (std::filesystem::path(base_path) / network_name / "sharechain_leveldb").string();
    
    // Configure optimized options for sharechain data
    m_options.write_buffer_size = 64 * 1024 * 1024;  // 64MB write buffer
    m_options.max_open_files = 1000;
    m_options.block_size = 16 * 1024;  // 16KB blocks
    m_options.block_cache_size = 256 * 1024 * 1024;  // 256MB cache
    m_options.bloom_filter_bits = 10;  // Bloom filter for fast lookups
    m_options.use_compression = true;   // Enable compression
    m_options.sync_writes = false;      // Async writes for performance
    m_options.verify_checksums = true;
    m_options.paranoid_checks = true;  // Detect corruption on read (~5% perf cost)
    
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

    // Check dirty flag — if set, previous shutdown was ungraceful.
    // Rebuild height index from share data to ensure consistency.
    std::vector<uint8_t> dirty_data;
    bool was_dirty = false;
    if (m_store->get("dirty", dirty_data) && !dirty_data.empty() && dirty_data[0] == 1) {
        was_dirty = true;
        LOG_WARNING << "SharechainLevelDB: dirty flag set — previous shutdown was ungraceful";
        LOG_INFO << "SharechainLevelDB: rebuilding height index...";
        // Scan all index: keys, re-read metadata, rebuild height: keys
        auto all_keys = m_store->list_keys("index:", std::numeric_limits<size_t>::max());
        int rebuilt = 0, removed_stale = 0;
        auto batch = m_store->create_batch();
        // First: remove all existing height: keys
        auto old_heights = m_store->list_keys("height:", std::numeric_limits<size_t>::max());
        for (const auto& hk : old_heights)
            batch.remove(hk);
        // Then: rebuild from index metadata
        for (const auto& idx_key : all_keys) {
            // idx_key = "index:<hash_hex>"
            std::string hash_hex = idx_key.substr(6);
            uint256 hash;
            hash.SetHex(hash_hex);
            std::string share_key = make_share_key(hash);
            if (!m_store->exists(share_key)) {
                // Stale index entry — share data missing
                batch.remove(idx_key);
                ++removed_stale;
                continue;
            }
            std::vector<uint8_t> meta_data;
            if (!m_store->get(idx_key, meta_data)) continue;
            try {
                PackStream ps(std::span<const std::byte>(
                    reinterpret_cast<const std::byte*>(meta_data.data()), meta_data.size()));
                uint256 prev; uint64_t height, ts; uint256 work, target; uint8_t orphan;
                ps >> prev >> height >> ts >> work >> target >> orphan;
                if (height > 0) {
                    std::string hk = make_height_key(height);
                    std::vector<uint8_t> hash_data(hash.data(), hash.data() + 32);
                    batch.put(hk, hash_data);
                    ++rebuilt;
                }
            } catch (...) {
                batch.remove(idx_key);
                ++removed_stale;
            }
        }
        batch.commit();
        // Update metadata
        m_metadata.total_shares = rebuilt;
        save_metadata();
        LOG_INFO << "SharechainLevelDB: rebuilt " << rebuilt << " height entries"
                 << " (removed " << removed_stale << " stale)";
    }

    // Set dirty flag — cleared on graceful close()
    {
        std::vector<uint8_t> flag = {1};
        m_store->put("dirty", flag);
    }

    LOG_INFO << "SharechainLevelDBStore opened for network: " << m_network_name;
    LOG_INFO << "  Database path: " << m_db_path;
    LOG_INFO << "  Stored shares: " << m_metadata.total_shares;
    LOG_INFO << "  Database version: " << m_metadata.version;
    if (was_dirty)
        LOG_INFO << "  Recovery: height index rebuilt from share metadata";

    return true;
}

void SharechainLevelDBStore::close()
{
    if (m_store && m_store->is_open()) {
        // Clear dirty flag — marks clean shutdown
        std::vector<uint8_t> flag = {0};
        m_store->put("dirty", flag);
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
        metadata_stream << static_cast<uint8_t>(metadata.is_verified ? 1 : 0);
        metadata_stream << metadata.pow_hash;

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

bool SharechainLevelDBStore::store_shares_batch(const std::vector<BatchShareEntry>& entries)
{
    if (!m_store || entries.empty())
        return true;

    try {
        auto batch = m_store->create_batch();

        for (const auto& e : entries) {
            // Share data
            batch.put(make_share_key(e.hash), e.serialized_share);

            // Index metadata
            PackStream metadata_stream;
            metadata_stream << e.metadata.prev_hash;
            metadata_stream << e.metadata.height;
            metadata_stream << e.metadata.timestamp;
            metadata_stream << e.metadata.work;
            metadata_stream << e.metadata.target;
            metadata_stream << static_cast<uint8_t>(e.metadata.is_orphan ? 1 : 0);
            metadata_stream << static_cast<uint8_t>(e.metadata.is_verified ? 1 : 0);
            metadata_stream << e.metadata.pow_hash;
            auto span = metadata_stream.get_span();
            std::vector<uint8_t> metadata_data(
                reinterpret_cast<const uint8_t*>(span.data()),
                reinterpret_cast<const uint8_t*>(span.data()) + span.size());
            batch.put(make_index_key(e.hash), metadata_data);

            // Height mapping
            if (e.metadata.height > 0) {
                std::vector<uint8_t> hash_data(e.hash.data(), e.hash.data() + 32);
                batch.put(make_height_key(e.metadata.height), hash_data);
            }
        }

        if (!batch.commit()) {
            LOG_ERROR << "Failed to commit share batch (" << entries.size() << " shares)";
            return false;
        }

        // Update in-memory metadata
        for (const auto& e : entries) {
            m_metadata.total_shares++;
            if (e.metadata.height > m_metadata.max_height) {
                m_metadata.max_height = e.metadata.height;
                m_metadata.best_hash = e.hash;
            }
        }

        return true;

    } catch (const std::exception& e) {
        LOG_ERROR << "Exception storing share batch: " << e.what();
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

        // is_verified: backward-compatible — old DBs won't have this byte
        try {
            uint8_t verified_flag;
            metadata_stream >> verified_flag;
            metadata.is_verified = (verified_flag != 0);
        } catch (...) {
            metadata.is_verified = false;
        }

        // pow_hash: backward-compatible — old DBs won't have this field
        try {
            metadata_stream >> metadata.pow_hash;
        } catch (...) {
            metadata.pow_hash = uint256::ZERO;
        }

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

bool SharechainLevelDBStore::remove_shares_batch(const std::vector<uint256>& hashes)
{
    if (!m_store || hashes.empty())
        return false;

    try {
        auto batch = m_store->create_batch();
        size_t removed = 0;

        for (const auto& hash : hashes)
        {
            // Load metadata for height key removal
            ShareMetadata metadata;
            std::vector<uint8_t> dummy;
            bool had_meta = load_share(hash, dummy, metadata);

            batch.remove(make_share_key(hash));
            batch.remove(make_index_key(hash));
            if (had_meta && metadata.height > 0)
                batch.remove(make_height_key(metadata.height));
            ++removed;
        }

        if (!batch.commit()) {
            LOG_ERROR << "[LevelDB] batch remove failed, count=" << hashes.size();
            return false;
        }

        if (m_metadata.total_shares >= removed)
            m_metadata.total_shares -= removed;
        else
            m_metadata.total_shares = 0;

        return true;
    } catch (const std::exception& e) {
        LOG_ERROR << "[LevelDB] batch remove exception: " << e.what();
        return false;
    }
}

bool SharechainLevelDBStore::mark_shares_verified(const std::vector<uint256>& hashes)
{
    if (!m_store || hashes.empty())
        return false;

    try {
        auto batch = m_store->create_batch();
        int updated = 0;

        for (const auto& hash : hashes) {
            ShareMetadata metadata;
            std::vector<uint8_t> dummy;
            if (!load_share(hash, dummy, metadata))
                continue;
            if (metadata.is_verified)
                continue; // already marked

            metadata.is_verified = true;

            PackStream ms;
            ms << metadata.prev_hash;
            ms << metadata.height;
            ms << metadata.timestamp;
            ms << metadata.work;
            ms << metadata.target;
            ms << static_cast<uint8_t>(metadata.is_orphan ? 1 : 0);
            ms << static_cast<uint8_t>(1); // is_verified = true
            ms << metadata.pow_hash;
            auto span = ms.get_span();
            std::vector<uint8_t> md(
                reinterpret_cast<const uint8_t*>(span.data()),
                reinterpret_cast<const uint8_t*>(span.data()) + span.size());
            batch.put(make_index_key(hash), md);
            ++updated;
        }

        if (updated > 0 && !batch.commit()) {
            LOG_ERROR << "mark_shares_verified: batch commit failed";
            return false;
        }
        return true;
    } catch (const std::exception& e) {
        LOG_ERROR << "mark_shares_verified failed: " << e.what();
        return false;
    }
}

bool SharechainLevelDBStore::mark_shares_verified_with_pow(
    const std::vector<std::pair<uint256, uint256>>& hash_pow_pairs)
{
    if (!m_store || hash_pow_pairs.empty())
        return false;
    try {
        auto batch = m_store->create_batch();
        int updated = 0;
        for (const auto& [hash, pow] : hash_pow_pairs) {
            ShareMetadata metadata;
            std::vector<uint8_t> dummy;
            if (!load_share(hash, dummy, metadata))
                continue;

            metadata.is_verified = true;
            if (!pow.IsNull())
                metadata.pow_hash = pow;

            PackStream ms;
            ms << metadata.prev_hash;
            ms << metadata.height;
            ms << metadata.timestamp;
            ms << metadata.work;
            ms << metadata.target;
            ms << static_cast<uint8_t>(metadata.is_orphan ? 1 : 0);
            ms << static_cast<uint8_t>(1);
            ms << metadata.pow_hash;
            auto span = ms.get_span();
            std::vector<uint8_t> md(
                reinterpret_cast<const uint8_t*>(span.data()),
                reinterpret_cast<const uint8_t*>(span.data()) + span.size());
            batch.put(make_index_key(hash), md);
            ++updated;
        }
        if (updated > 0 && !batch.commit()) {
            LOG_ERROR << "mark_shares_verified_with_pow: batch commit failed";
            return false;
        }
        return true;
    } catch (const std::exception& e) {
        LOG_ERROR << "mark_shares_verified_with_pow failed: " << e.what();
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

    // Use LevelDB iterator with seek — O(stored shares) not O(max_height).
    // Old code did point lookups for every height 0..max_height (26M+ lookups).
    // Height keys are "height:XXXXXXXXXXXXXXXX" with zero-padded 16-digit height,
    // so lexicographic iteration gives us sorted height order.
    try {
        std::string start_key = make_height_key(start_height);
        std::string end_key = make_height_key(end_height);
        std::string prefix = "height:";

        // Seek to start_key, iterate while keys have "height:" prefix and <= end_key
        auto all_height_keys = m_store->list_keys(prefix, std::numeric_limits<size_t>::max());
        for (const auto& key : all_height_keys) {
            if (key < start_key) continue;
            if (key > end_key) break;
            std::vector<uint8_t> hash_data;
            if (m_store->get(key, hash_data) && hash_data.size() == 32) {
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
