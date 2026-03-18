#pragma once

#include <string>
#include <vector>
#include <cstdint>
#include <core/leveldb_store.hpp>
#include <core/uint256.hpp>
#include <core/log.hpp>
#include <core/pack.hpp>

namespace c2pool {
namespace storage {

/// Persistent record for a found block (Layer +2 in THE terminology).
/// Never pruned — these represent actual blockchain economic events.
struct FoundBlockRecord {
    std::string chain;              // "LTC"/"tLTC"/"DOGE" etc
    uint64_t    height{0};          // parent chain block height
    std::string block_hash;         // parent chain block hash hex
    uint64_t    timestamp{0};       // when found (unix seconds)
    uint8_t     status{0};          // 0=pending, 1=confirmed, 2=orphaned, 3=stale
    uint8_t     check_count{0};     // verification attempts so far
    uint64_t    last_checked{0};    // timestamp of last verification
    uint32_t    confirmations{0};   // last known confirmation count
    std::string finder_address;     // miner who found the block (if known)
    uint64_t    reward_satoshis{0}; // coinbase reward amount (if known)
    uint256     the_state_root;     // THE commitment embedded in coinbase scriptSig

    // Serialize to bytes for LevelDB storage
    std::vector<uint8_t> serialize() const
    {
        PackStream ps;
        // Version byte for future extensibility
        uint8_t version = 1;
        ps << version;
        // Chain as length-prefixed string
        uint8_t chain_len = static_cast<uint8_t>(std::min(chain.size(), size_t(255)));
        ps << chain_len;
        ps.write(std::span<const std::byte>(
            reinterpret_cast<const std::byte*>(chain.data()), chain_len));
        ps << height;
        // block_hash as length-prefixed string
        uint8_t hash_len = static_cast<uint8_t>(std::min(block_hash.size(), size_t(255)));
        ps << hash_len;
        ps.write(std::span<const std::byte>(
            reinterpret_cast<const std::byte*>(block_hash.data()), hash_len));
        ps << timestamp;
        ps << status;
        ps << check_count;
        ps << last_checked;
        ps << confirmations;
        // finder_address
        uint8_t addr_len = static_cast<uint8_t>(std::min(finder_address.size(), size_t(255)));
        ps << addr_len;
        if (addr_len > 0)
            ps.write(std::span<const std::byte>(
                reinterpret_cast<const std::byte*>(finder_address.data()), addr_len));
        ps << reward_satoshis;

        auto span = ps.get_span();
        return {reinterpret_cast<const uint8_t*>(span.data()),
                reinterpret_cast<const uint8_t*>(span.data()) + span.size()};
    }

    // Deserialize from bytes
    static FoundBlockRecord deserialize(const std::vector<uint8_t>& data)
    {
        FoundBlockRecord rec;
        if (data.size() < 4) return rec;

        size_t pos = 0;
        auto read_u8 = [&]() -> uint8_t {
            return pos < data.size() ? data[pos++] : 0;
        };
        auto read_u32 = [&]() -> uint32_t {
            if (pos + 4 > data.size()) return 0;
            uint32_t v;
            std::memcpy(&v, &data[pos], 4);
            pos += 4;
            return v;
        };
        auto read_u64 = [&]() -> uint64_t {
            if (pos + 8 > data.size()) return 0;
            uint64_t v;
            std::memcpy(&v, &data[pos], 8);
            pos += 8;
            return v;
        };
        auto read_str = [&](uint8_t len) -> std::string {
            if (pos + len > data.size()) { pos = data.size(); return ""; }
            std::string s(reinterpret_cast<const char*>(&data[pos]), len);
            pos += len;
            return s;
        };

        uint8_t version = read_u8();
        if (version != 1) return rec; // unknown version

        uint8_t chain_len = read_u8();
        rec.chain = read_str(chain_len);
        rec.height = read_u64();
        uint8_t hash_len = read_u8();
        rec.block_hash = read_str(hash_len);
        rec.timestamp = read_u64();
        rec.status = read_u8();
        rec.check_count = read_u8();
        rec.last_checked = read_u64();
        rec.confirmations = read_u32();
        uint8_t addr_len = read_u8();
        rec.finder_address = read_str(addr_len);
        rec.reward_satoshis = read_u64();

        return rec;
    }
};

/// LevelDB-backed persistent store for found blocks.
/// Uses key prefix "fblk:" to share the same LevelDB instance as shares.
/// Never pruned — found blocks are permanent Layer +2 records.
class FoundBlockStore {
public:
    explicit FoundBlockStore(core::LevelDBStore& store) : m_store(store) {}

    /// Store a found block record
    bool store(const FoundBlockRecord& rec)
    {
        auto key = make_key(rec.chain, rec.height, rec.block_hash);
        auto data = rec.serialize();
        return m_store.put(key, data);
    }

    /// Update status of an existing record
    bool update_status(const std::string& chain, uint64_t height,
                       const std::string& block_hash,
                       uint8_t new_status, uint8_t check_count,
                       uint32_t confirmations)
    {
        auto key = make_key(chain, height, block_hash);
        std::vector<uint8_t> data;
        if (!m_store.get(key, data))
            return false;

        auto rec = FoundBlockRecord::deserialize(data);
        rec.status = new_status;
        rec.check_count = check_count;
        rec.confirmations = confirmations;
        rec.last_checked = static_cast<uint64_t>(std::time(nullptr));

        return m_store.put(key, rec.serialize());
    }

    /// Load all found blocks (newest first by height)
    std::vector<FoundBlockRecord> load_all()
    {
        std::vector<FoundBlockRecord> result;

        // Scan all keys with "fblk:" prefix
        auto keys = m_store.list_keys("fblk:", 10000);
        for (const auto& key : keys)
        {
            std::vector<uint8_t> data;
            if (m_store.get(key, data))
            {
                auto rec = FoundBlockRecord::deserialize(data);
                if (!rec.block_hash.empty())
                    result.push_back(std::move(rec));
            }
        }

        // Sort newest first
        std::sort(result.begin(), result.end(),
            [](const FoundBlockRecord& a, const FoundBlockRecord& b) {
                return a.timestamp > b.timestamp;
            });

        return result;
    }

    /// Count stored found blocks
    size_t count()
    {
        return m_store.list_keys("fblk:", 10000).size();
    }

private:
    core::LevelDBStore& m_store;

    static std::string make_key(const std::string& chain, uint64_t height,
                                const std::string& block_hash)
    {
        // Key format: fblk:<chain>:<zero-padded-height>:<hash>
        // Zero-padding ensures lexicographic = chronological ordering
        std::ostringstream oss;
        oss << "fblk:" << chain << ":"
            << std::setfill('0') << std::setw(12) << height << ":"
            << block_hash.substr(0, 16); // truncate hash in key (full hash in value)
        return oss.str();
    }
};

} // namespace storage
} // namespace c2pool
