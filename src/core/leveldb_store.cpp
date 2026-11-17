#include "leveldb_store.hpp"
#include <core/log.hpp>
#include <core/pack.hpp>
#include <leveldb/write_batch.h>
#include <leveldb/filter_policy.h>
#include <leveldb/cache.h>
#include <core/leveldb_pread_env.hpp>
#include <algorithm>
#include <cstring>
#include <filesystem>
#include <limits>
#include <map>
#include <mutex>
#include <optional>
#include <set>
#include <thread>
#include <sstream>

namespace core {

namespace {

/// LevelDB could not take the DB's LOCK. The status names the file,
/// leveldb::LockFileName(dbname) = dbname + "/LOCK", on every platform:
/// env_posix "lock <dir>/LOCK: Resource temporarily unavailable" or "...
/// already held by process"; env_windows "<dir>/LOCK: <sharing violation>"
/// (CreateFileA fails before LockFileEx, without the "lock " prefix).
bool status_lock_held(const leveldb::Status& status, const std::string& db_path)
{
    return status.IsIOError() && status.ToString().find(db_path + "/LOCK") != std::string::npos;
}

/// The DBs this process has open (canonical paths): a second open of one is
/// refused before LevelDB sees it.
std::mutex& registry_mutex()
{
    static std::mutex mu;
    return mu;
}

std::set<std::string>& registry()
{
    static std::set<std::string> open_paths;
    return open_paths;
}

std::string registry_key(const std::string& db_path)
{
    std::error_code ec;
    auto p = std::filesystem::weakly_canonical(std::filesystem::path(db_path), ec);
    return ec ? std::filesystem::absolute(db_path, ec).lexically_normal().string() : p.string();
}

void unregister(std::string& key)
{
    if (key.empty())
        return;
    std::lock_guard<std::mutex> lock(registry_mutex());
    registry().erase(key);
    key.clear();
}

// The height index (leveldb_store.hpp): `height:<h>` holds ONE 32-byte hash,
// exactly as every earlier binary wrote and reads it (the primary); every
// other stored share of absheight h has a key of its own, `hsib:<h><hash>`.
constexpr size_t kHashBytes = 32;
const std::string kHeightPrefix = "height:";
const std::string kSiblingPrefix = "hsib:";

std::string height_digits(uint64_t height)
{
    std::ostringstream oss;
    oss << std::setfill('0') << std::setw(16) << height;
    return oss.str();
}

std::string sibling_prefix(uint64_t height) { return kSiblingPrefix + height_digits(height); }

std::string sibling_key(uint64_t height, const uint256& hash) { return sibling_prefix(height) + hash.ToString(); }

std::vector<uint8_t> hash_bytes(const uint256& hash)
{
    return std::vector<uint8_t>(hash.data(), hash.data() + kHashBytes);
}

uint256 hash_from_bytes(const uint8_t* p)
{
    std::vector<unsigned char> v(p, p + kHashBytes);
    return uint256(v);
}

// Every stored share of one absheight, as the store holds it and as it held
// it when read (only the difference is written back).
struct HeightSlot
{
    std::optional<uint256> primary, primary0;
    std::set<uint256> siblings, siblings0;

    void add(const uint256& hash)
    {
        if (!primary)
            primary = hash;
        else if (*primary != hash)
            siblings.insert(hash);
    }
    // Removes `hash` and only it. A removed primary is replaced by a sibling:
    // the `height:` key goes only with the last share of the height.
    void erase(const uint256& hash)
    {
        if (primary && *primary == hash) {
            primary.reset();
            if (!siblings.empty()) {
                primary = *siblings.begin();
                siblings.erase(siblings.begin());
            }
        } else {
            siblings.erase(hash);
        }
    }
};

// Reads the slot of `height`. False on a read error (an absent key is not one).
bool load_height_slot(LevelDBStore& store, const std::string& height_key, uint64_t height, HeightSlot& slot)
{
    std::vector<uint8_t> value;
    bool found = false;
    if (!store.lookup(height_key, value, found))
        return false;
    if (found && value.size() == kHashBytes)
        slot.primary = hash_from_bytes(value.data());
    const std::string prefix = sibling_prefix(height);
    const bool scanned = store.for_each_prefix(prefix, [&](const std::string& key, const std::vector<uint8_t>&) {
        if (key.size() == prefix.size() + 64) {
            uint256 hash;
            hash.SetHex(key.substr(prefix.size()));
            if (!slot.primary || *slot.primary != hash)
                slot.siblings.insert(hash);
        }
        return true;
    });
    if (!scanned)
        return false;
    slot.primary0 = slot.primary;
    slot.siblings0 = slot.siblings;
    if (!slot.primary && !slot.siblings.empty()) {   // not a state this store leaves: repair
        slot.primary = *slot.siblings.begin();
        slot.siblings.erase(slot.siblings.begin());
    }
    return true;
}

void stage_height_slot(LevelDBStore::BatchWriter& batch, const std::string& height_key, uint64_t height,
                       const HeightSlot& slot)
{
    if (slot.primary != slot.primary0) {
        if (slot.primary)
            batch.put(height_key, hash_bytes(*slot.primary));
        else
            batch.remove(height_key);
    }
    for (const auto& hash : slot.siblings0)
        if (!slot.siblings.count(hash))
            batch.remove(sibling_key(height, hash));
    for (const auto& hash : slot.siblings)
        if (!slot.siblings0.count(hash))
            batch.put(sibling_key(height, hash), hash_bytes(hash));
}

// The parent, absheight and verified flag of an `index:` record (see
// store_share for its layout; the verified byte is absent in the oldest).
bool parse_index_value(const std::vector<uint8_t>& meta, uint256& prev, uint64_t& height, bool& is_verified)
{
    try {
        PackStream ps(std::span<const std::byte>(
            reinterpret_cast<const std::byte*>(meta.data()), meta.size()));
        uint256 work, target;
        uint64_t ts = 0;
        uint8_t orphan = 0;
        ps >> prev >> height >> ts >> work >> target >> orphan;
        is_verified = false;
        try {
            uint8_t verified = 0;
            ps >> verified;
            is_verified = verified != 0;
        } catch (...) {}
        return true;
    } catch (...) {
        return false;
    }
}

} // namespace

bool leveldb_status_lock_held(const leveldb::Status& status, const std::string& db_path)
{
    return status_lock_held(status, db_path);
}

LevelDBStore::LevelDBStore(const std::string& db_path, const LevelDBOptions& options)
    : m_db_path(db_path), m_options(options), m_db(nullptr)
{
}

struct LevelDBStore::SnapshotRegistry {
    std::mutex mu;
    leveldb::DB* db = nullptr;   // null once the store closed
    std::set<const leveldb::Snapshot*> live;
};

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

    m_lock_held = false;
    try {
        // Create directory if it doesn't exist
        std::filesystem::create_directories(m_db_path);

        // Another LevelDBStore of this process has it open.
        {
            const std::string key = registry_key(m_db_path);
            std::lock_guard<std::mutex> lock(registry_mutex());
            if (!registry().insert(key).second) {
                m_lock_held = true;
                LOG_ERROR << "LevelDB at " << m_db_path << " is already open in this process; not opened "
                          << "again, and nothing in it touched. " << held_advice();
                return false;
            }
            m_registered = key;
        }

        // Configure LevelDB options
        leveldb::Options db_options;
        db_options.create_if_missing = true;
        db_options.error_if_exists = false;
        db_options.paranoid_checks = m_options.paranoid_checks;
        db_options.write_buffer_size = m_options.write_buffer_size;
        db_options.max_open_files = m_options.max_open_files;
        db_options.max_file_size = m_options.max_file_size;
        if (!m_options.mmap_reads)
            if (leveldb::Env* env = leveldb_pread_env())
                db_options.env = env;
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

        // A LOCK that LevelDB cannot take is held by an open DB: another
        // process (an fcntl lock: the kernel releases a dead holder's, so a
        // held lock is never stale), or another handle in this process. Fail
        // as Bitcoin Core does ("Cannot obtain a lock"): never unlink LOCK,
        // never repair a live DB. Unlinking it let a second process
        // (--utxo-digest) open a live IBD's full UTXO set beside it: 68 table
        // files went missing and a 4.75 M-height set was lost. A LOCK file
        // nobody holds (left by a crash) does not stop the open.
        if (!status.ok() && status_lock_held(status, m_db_path)) {
            m_lock_held = true;
            unregister(m_registered);
            LOG_ERROR << "LevelDB at " << m_db_path << " is in use (" << status.ToString()
                      << "): another process holds its lock; not opened, and nothing in it touched. "
                      << held_advice();
            return false;
        }

        if (!status.ok()) {
            LOG_WARNING << "LevelDB open failed at " << m_db_path
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
            unregister(m_registered);
            LOG_ERROR << "Failed to open LevelDB at " << m_db_path << ": " << status.ToString();
            return false;
        }

        m_db.reset(db_ptr);
        m_snapshots = std::make_shared<SnapshotRegistry>();
        m_snapshots->db = db_ptr;
        LOG_INFO << "LevelDB store opened successfully at: " << m_db_path;
        return true;

    } catch (const std::exception& e) {
        unregister(m_registered);
        LOG_ERROR << "Exception opening LevelDB: " << e.what();
        return false;
    }
}

bool LevelDBStore::open_waiting(int attempts, std::chrono::milliseconds wait)
{
    for (int attempt = 1;; ++attempt) {
        if (open())
            return true;
        if (!m_lock_held || attempt >= attempts)
            return false;
        LOG_WARNING << "LevelDB at " << m_db_path << " is held by another open (attempt " << attempt << "/"
                    << attempts << "): the process it replaces may still be exiting; again in "
                    << wait.count() << " ms (if not, " << held_advice() << ")";
        std::this_thread::sleep_for(wait);
    }
}

void LevelDBStore::close()
{
    if (m_snapshots) {
        // Snapshots still held are released here, while the DB exists; their
        // copies then release nothing.
        std::lock_guard<std::mutex> lock(m_snapshots->mu);
        for (const leveldb::Snapshot* s : m_snapshots->live)
            m_snapshots->db->ReleaseSnapshot(s);
        m_snapshots->live.clear();
        m_snapshots->db = nullptr;
    }
    m_snapshots.reset();
    if (m_db) {
        LOG_INFO << "Closing LevelDB store at: " << m_db_path;
        m_db.reset();
    }
    unregister(m_registered);
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

bool LevelDBStore::lookup(const std::string& key, std::vector<uint8_t>& value, bool& found)
{
    found = false;
    value.clear();
    if (!m_db) {
        LOG_ERROR << "LevelDB store not open";
        return false;
    }
    leveldb::ReadOptions read_options;
    read_options.verify_checksums = m_options.verify_checksums;
    std::string raw_value;
    leveldb::Status status = m_db->Get(read_options, key, &raw_value);
    if (status.IsNotFound())
        return true;
    if (!status.ok()) {
        LOG_ERROR << "Failed to get key '" << key << "': " << status.ToString();
        return false;
    }
    value.assign(raw_value.begin(), raw_value.end());
    found = true;
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

bool LevelDBStore::for_each_prefix(const std::string& prefix,
                                   const std::function<bool(const std::string& key,
                                                            const std::vector<uint8_t>& value)>& fn)
{
    if (!m_db) {
        LOG_ERROR << "LevelDB store not open";
        return false;
    }

    std::unique_ptr<leveldb::Iterator> it(m_db->NewIterator(leveldb::ReadOptions()));

    if (prefix.empty()) {
        it->SeekToFirst();
    } else {
        it->Seek(prefix);
    }

    std::vector<uint8_t> value;
    for (; it->Valid(); it->Next()) {
        leveldb::Slice key = it->key();
        if (!prefix.empty() &&
            (key.size() < prefix.size() ||
             std::memcmp(key.data(), prefix.data(), prefix.size()) != 0)) {
            break;  // past the prefix range — done
        }
        leveldb::Slice val = it->value();
        value.assign(reinterpret_cast<const uint8_t*>(val.data()),
                     reinterpret_cast<const uint8_t*>(val.data()) + val.size());
        if (!fn(key.ToString(), value))
            return true;  // caller-requested early stop is not an error
    }

    if (!it->status().ok()) {
        LOG_ERROR << "Error scanning prefix: " << it->status().ToString();
        return false;
    }

    return true;
}

LevelDBStore::Snapshot LevelDBStore::snapshot()
{
    if (!m_db || !m_snapshots)
        return nullptr;
    std::shared_ptr<SnapshotRegistry> reg = m_snapshots;
    std::lock_guard<std::mutex> lock(reg->mu);
    const leveldb::Snapshot* snap = reg->db->GetSnapshot();
    reg->live.insert(snap);
    return Snapshot(snap, [reg](const leveldb::Snapshot* s) {
        std::lock_guard<std::mutex> l(reg->mu);
        if (reg->db && reg->live.erase(s) != 0)
            reg->db->ReleaseSnapshot(s);
    });
}

bool LevelDBStore::for_each_prefix_at(const Snapshot& at, const std::string& prefix,
                                      const std::function<bool(std::string_view key,
                                                               std::string_view value)>& fn)
{
    if (!m_db) {
        LOG_ERROR << "LevelDB store not open";
        return false;
    }
    if (at) {
        // A snapshot of an earlier open was released by its close().
        std::lock_guard<std::mutex> lock(m_snapshots->mu);
        if (m_snapshots->live.count(at.get()) == 0) {
            LOG_ERROR << "LevelDB snapshot is not of this open of " << m_db_path;
            return false;
        }
    }
    leveldb::ReadOptions ro;
    ro.snapshot = at.get();
    ro.fill_cache = false;
    std::unique_ptr<leveldb::Iterator> it(m_db->NewIterator(ro));
    if (prefix.empty())
        it->SeekToFirst();
    else
        it->Seek(prefix);
    for (; it->Valid(); it->Next()) {
        const leveldb::Slice key = it->key();
        if (!prefix.empty() &&
            (key.size() < prefix.size() ||
             std::memcmp(key.data(), prefix.data(), prefix.size()) != 0))
            break;
        const leveldb::Slice val = it->value();
        if (!fn(std::string_view(key.data(), key.size()), std::string_view(val.data(), val.size())))
            return true;   // caller-requested early stop is not an error
    }
    if (!it->status().ok()) {
        LOG_ERROR << "Error scanning prefix: " << it->status().ToString();
        return false;
    }
    return true;
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

    // The dirty flag: 1 while open (an ungraceful shutdown leaves it), and the
    // value close() writes. This binary writes kCleanClose (2); every earlier
    // binary writes 0 and treats only 1 as dirty. So anything but 2 means the
    // height index was last written by a binary that does not keep every
    // share of a height in it (or the shutdown was ungraceful): rebuild it
    // from the share records, as the ungraceful-shutdown path always did.
    std::vector<uint8_t> dirty_data;
    bool was_dirty = false;
    const bool has_flag = m_store->get("dirty", dirty_data) && !dirty_data.empty();
    const uint8_t flag = has_flag ? dirty_data[0] : 0;
    if (flag == 1) {
        was_dirty = true;
        LOG_WARNING << "SharechainLevelDB: dirty flag set — previous shutdown was ungraceful";
        rebuild_height_index("ungraceful shutdown");
    } else if (flag != kCleanClose && !m_store->list_keys("index:", 1).empty()) {
        rebuild_height_index(has_flag ? "last closed by a binary without the per-share height index"
                                      : "no close recorded");
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

bool SharechainLevelDBStore::open_waiting(int attempts, std::chrono::milliseconds wait)
{
    for (int attempt = 1;; ++attempt) {
        if (open())
            return true;
        if (!lock_held() || attempt >= attempts)
            return false;
        LOG_WARNING << "SharechainLevelDB at " << m_db_path << " is held by another open (attempt " << attempt
                    << "/" << attempts << "): the process it replaces may still be exiting; again in "
                    << wait.count() << " ms (if not, " << LevelDBStore::held_advice() << ")";
        std::this_thread::sleep_for(wait);
    }
}

void SharechainLevelDBStore::close()
{
    if (m_store && m_store->is_open()) {
        // Clean shutdown by this binary (see open()): kCleanClose, not the 0
        // earlier binaries write, so a later open can tell they ran.
        std::vector<uint8_t> flag = {kCleanClose};
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

void SharechainLevelDBStore::rebuild_height_index(const char* why)
{
    LOG_INFO << "SharechainLevelDB: rebuilding height index (" << why << ")...";
    const auto t0 = std::chrono::steady_clock::now();
    struct Row { uint256 hash; uint256 prev; uint64_t height; bool verified; };
    std::vector<Row> rows;
    std::vector<std::string> stale;
    const bool scanned = m_store->for_each_prefix(
        "index:", [&](const std::string& idx_key, const std::vector<uint8_t>& meta) {
            // idx_key = "index:<hash_hex>"
            Row row{};
            row.hash.SetHex(idx_key.substr(6));
            // Share data missing, or metadata unreadable: a stale index entry.
            if (!m_store->exists(make_share_key(row.hash))
                || !parse_index_value(meta, row.prev, row.height, row.verified)) {
                stale.push_back(idx_key);
                return true;
            }
            rows.push_back(row);
            return true;
        });
    if (!scanned) {
        LOG_ERROR << "SharechainLevelDB: index scan failed; height index left as it was";
        return;
    }

    // The primary of a height (its `height:` key, the one share every earlier
    // binary reads) is the share on the best chain: the longest run of parent
    // links through the stored shares, ties to the higher tip. Off that chain,
    // a verified share, else the first by hash.
    std::map<uint256, size_t> pos;
    for (size_t i = 0; i < rows.size(); ++i)
        pos.emplace(rows[i].hash, i);
    std::vector<uint64_t> depth(rows.size(), 0);
    for (size_t i = 0; i < rows.size(); ++i) {
        if (depth[i])
            continue;
        std::vector<size_t> path;
        size_t cur = i;
        uint64_t base = 0;
        while (true) {
            path.push_back(cur);
            auto it = pos.find(rows[cur].prev);
            if (it == pos.end())
                break;
            if (depth[it->second]) {
                base = depth[it->second];
                break;
            }
            if (path.size() > rows.size())   // a parent cycle: not a chain
                break;
            cur = it->second;
        }
        for (size_t k = path.size(); k-- > 0;)
            if (!depth[path[k]])
                depth[path[k]] = ++base;
    }
    std::vector<bool> on_best(rows.size(), false);
    size_t best_len = 0;
    if (!rows.empty()) {
        size_t tip = 0;
        for (size_t i = 1; i < rows.size(); ++i)
            if (depth[i] > depth[tip] || (depth[i] == depth[tip] && rows[i].height > rows[tip].height))
                tip = i;
        for (size_t cur = tip;;) {
            if (on_best[cur])
                break;
            on_best[cur] = true;
            ++best_len;
            auto it = pos.find(rows[cur].prev);
            if (it == pos.end())
                break;
            cur = it->second;
        }
    }
    std::map<uint64_t, std::vector<size_t>> by_height;
    for (size_t i = 0; i < rows.size(); ++i)
        if (rows[i].height > 0)
            by_height[rows[i].height].push_back(i);

    auto batch = m_store->create_batch();
    for (const auto& key : m_store->list_keys(kHeightPrefix, std::numeric_limits<size_t>::max()))
        batch.remove(key);
    for (const auto& key : m_store->list_keys(kSiblingPrefix, std::numeric_limits<size_t>::max()))
        batch.remove(key);
    size_t with_siblings = 0;
    for (const auto& [height, idx] : by_height) {
        size_t primary = idx.front();
        for (size_t i : idx)
            if (on_best[i]) { primary = i; break; }
        if (!on_best[primary])
            for (size_t i : idx)
                if (rows[i].verified) { primary = i; break; }
        batch.put(make_height_key(height), hash_bytes(rows[primary].hash));
        for (size_t i : idx)
            if (i != primary)
                batch.put(sibling_key(height, rows[i].hash), hash_bytes(rows[i].hash));
        with_siblings += idx.size() > 1 ? 1 : 0;
    }
    for (const auto& idx_key : stale)
        batch.remove(idx_key);
    if (!batch.commit()) {
        LOG_ERROR << "SharechainLevelDB: height index rebuild failed to commit";
        return;
    }
    m_metadata.total_shares = rows.size();
    save_metadata();
    LOG_INFO << "SharechainLevelDB: rebuilt height index: " << rows.size() << " shares at "
             << by_height.size() << " heights (" << with_siblings << " with more than one share; best chain "
             << best_len << " shares; removed " << stale.size() << " stale) in "
             << std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::steady_clock::now() - t0).count()
             << " ms";
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

        // Height index: the share joins its height's slot (the `height:` key
        // when it is the first share of the height, else a `hsib:` key).
        if (metadata.height > 0) {
            const std::string height_key = make_height_key(metadata.height);
            HeightSlot slot;
            if (!load_height_slot(*m_store, height_key, metadata.height, slot)) {
                LOG_ERROR << "Failed to store share " << hash.ToString()
                          << ": height index unreadable at " << metadata.height;
                return false;
            }
            slot.add(hash);
            stage_height_slot(batch, height_key, metadata.height, slot);
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
        // The height slots this batch changes, read once from the store and
        // then kept here: a batch's own puts are not visible to reads.
        std::map<uint64_t, HeightSlot> heights;

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

            // Height index (see store_share)
            if (e.metadata.height > 0) {
                auto [it, fresh] = heights.try_emplace(e.metadata.height);
                if (fresh && !load_height_slot(*m_store, make_height_key(e.metadata.height),
                                               e.metadata.height, it->second)) {
                    LOG_ERROR << "Failed to store share batch (" << entries.size()
                              << " shares): height index unreadable at " << e.metadata.height;
                    return false;
                }
                it->second.add(e.hash);
            }
        }
        for (const auto& [height, slot] : heights)
            stage_height_slot(batch, make_height_key(height), height, slot);

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
        
        // Only this share leaves its height's slot: a removed `height:` share is
        // replaced by another share of the height, and the key goes only with
        // the last one. Deleting the key whatever it held dropped the other
        // shares of the height with it — the main-chain share whenever a fork
        // share of its height was pruned.
        if (had_metadata && metadata.height > 0) {
            const std::string height_key = make_height_key(metadata.height);
            HeightSlot slot;
            if (!load_height_slot(*m_store, height_key, metadata.height, slot)) {
                LOG_ERROR << "Failed to remove share " << hash.ToString()
                          << ": height index unreadable at " << metadata.height;
                return false;
            }
            slot.erase(hash);
            stage_height_slot(batch, height_key, metadata.height, slot);
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
        // The height slots this batch changes (see store_shares_batch).
        std::map<uint64_t, HeightSlot> heights;

        for (const auto& hash : hashes)
        {
            // Load metadata for height key removal
            ShareMetadata metadata;
            std::vector<uint8_t> dummy;
            bool had_meta = load_share(hash, dummy, metadata);

            batch.remove(make_share_key(hash));
            batch.remove(make_index_key(hash));
            // Only this share leaves its height's slot (see remove_share).
            if (had_meta && metadata.height > 0) {
                auto [it, fresh] = heights.try_emplace(metadata.height);
                if (fresh && !load_height_slot(*m_store, make_height_key(metadata.height),
                                               metadata.height, it->second)) {
                    LOG_ERROR << "[LevelDB] batch remove failed (" << hashes.size()
                              << " shares): height index unreadable at " << metadata.height;
                    return false;
                }
                it->second.erase(hash);
            }
            ++removed;
        }
        for (const auto& [height, slot] : heights)
            stage_height_slot(batch, make_height_key(height), height, slot);

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
                HeightSlot slot;
                if (!load_height_slot(*m_store, make_height_key(current_height), current_height, slot)
                    || !slot.primary) {
                    break; // No more shares in chain
                }
                
                // The share of the next height whose parent is this one.
                std::vector<uint256> candidates{*slot.primary};
                candidates.insert(candidates.end(), slot.siblings.begin(), slot.siblings.end());
                bool found = false;
                for (const auto& next : candidates) {
                    ShareMetadata next_meta;
                    if (load_share(next, dummy_data, next_meta) && next_meta.prev_hash == current_hash) {
                        current_hash = next;
                        found = true;
                        break;
                    }
                }
                if (!found)
                    break;
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

    // Every stored share of each height in the range, in height order: the
    // `height:` share first, then the `hsib:` shares of that height. Height
    // keys are zero-padded to 16 digits, so key order is height order.
    try {
        std::map<uint64_t, std::vector<uint256>> by_height;
        const std::string start_key = make_height_key(start_height);
        const std::string end_key = make_height_key(end_height);
        for (const auto& key : m_store->list_keys(kHeightPrefix, std::numeric_limits<size_t>::max())) {
            if (key.size() != kHeightPrefix.size() + 16) continue;   // not a key this store writes
            if (key < start_key) continue;
            if (key > end_key) break;
            std::vector<uint8_t> hash_data;
            if (m_store->get(key, hash_data) && hash_data.size() == kHashBytes)
                by_height[std::stoull(key.substr(kHeightPrefix.size()))].push_back(hash_from_bytes(hash_data.data()));
        }
        for (const auto& key : m_store->list_keys(kSiblingPrefix, std::numeric_limits<size_t>::max())) {
            if (key.size() != kSiblingPrefix.size() + 16 + 64)
                continue;
            const uint64_t height = std::stoull(key.substr(kSiblingPrefix.size(), 16));
            if (height < start_height || height > end_height)
                continue;
            uint256 hash;
            hash.SetHex(key.substr(kSiblingPrefix.size() + 16));
            auto& at = by_height[height];
            if (std::find(at.begin(), at.end(), hash) == at.end())
                at.push_back(hash);
        }
        for (const auto& [height, at] : by_height)
            hashes.insert(hashes.end(), at.begin(), at.end());
    } catch (const std::exception& e) {
        LOG_ERROR << "Exception getting shares by height range: " << e.what();
        hashes.clear();
    }

    return hashes;
}

bool SharechainLevelDBStore::scan_share_index(std::vector<IndexEntry>& out)
{
    out.clear();
    if (!m_store || !m_store->is_open())
        return false;
    const std::string prefix = "index:";
    const bool ok = m_store->for_each_prefix(
        prefix, [&](const std::string& key, const std::vector<uint8_t>& meta) {
            if (key.size() != prefix.size() + 64)
                return true;   // not a key this store wrote
            IndexEntry e;
            e.hash.SetHex(key.substr(prefix.size()));
            uint256 prev;
            if (parse_index_value(meta, prev, e.height, e.is_verified))
                out.push_back(e);
            return true;
        });
    if (!ok) {
        out.clear();
        return false;
    }
    std::sort(out.begin(), out.end(), [](const IndexEntry& a, const IndexEntry& b) {
        return a.height != b.height ? a.height < b.height : a.hash < b.hash;
    });
    return true;
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
