#pragma once
// the_checkpoint.hpp — THE checkpoint verification and fast-sync support
//
// Checkpoints are created whenever c2pool finds a block (parent or merged).
// Each checkpoint records:
//   - the_state_root: SHA256d Merkle of (L-1, L0_pplns, L+1, epoch_meta)
//   - sharechain_height: height of best share at block-find time
//   - miner_count: unique miners in PPLNS window
//   - block_hash: the blockchain block that carries this commitment
//   - chain: which blockchain ("LTC", "tLTC", "DOGE", etc.)
//   - status: pending → verified (recomputed and matches) or mismatch
//
// On startup, the node loads the latest verified checkpoint from LevelDB
// and can use it to:
//   1. Verify sharechain integrity (recompute state_root, compare)
//   2. Skip downloading shares older than checkpoint (fast sync)
//   3. Serve /checkpoint endpoint for light clients

#include <string>
#include <vector>
#include <cstdint>
#include <cstring>
#include <ctime>
#include <optional>
#include <core/uint256.hpp>
#include <core/leveldb_store.hpp>
#include <core/log.hpp>
#include <core/coinbase_builder.hpp>

namespace c2pool {
namespace storage {

/// A THE checkpoint: on-chain commitment of sharechain state
struct TheCheckpoint {
    uint256     the_state_root;         // committed in coinbase scriptSig
    uint32_t    sharechain_height{0};   // best share height at block-find
    uint16_t    miner_count{0};         // miners in PPLNS window
    uint8_t     hashrate_class{0};      // log2(pool H/s)
    std::string chain;                  // "LTC"/"tLTC"/"DOGE" etc
    uint64_t    block_height{0};        // blockchain block height
    std::string block_hash;             // blockchain block hash
    uint64_t    timestamp{0};           // when found
    uint8_t     status{0};              // 0=pending, 1=verified, 2=mismatch

    std::vector<uint8_t> serialize() const {
        std::vector<uint8_t> out;
        out.reserve(128);
        out.push_back(0x01); // version

        // state_root (32 bytes)
        out.insert(out.end(), the_state_root.data(), the_state_root.data() + 32);

        // sharechain_height (4 bytes LE)
        for (int i = 0; i < 4; ++i) out.push_back((sharechain_height >> (8*i)) & 0xff);

        // miner_count (2 bytes LE)
        out.push_back(miner_count & 0xff);
        out.push_back((miner_count >> 8) & 0xff);

        // hashrate_class (1 byte)
        out.push_back(hashrate_class);

        // chain (length-prefixed)
        out.push_back(static_cast<uint8_t>(chain.size()));
        out.insert(out.end(), chain.begin(), chain.end());

        // block_height (8 bytes LE)
        for (int i = 0; i < 8; ++i) out.push_back((block_height >> (8*i)) & 0xff);

        // block_hash (length-prefixed)
        out.push_back(static_cast<uint8_t>(std::min(block_hash.size(), size_t(255))));
        out.insert(out.end(), block_hash.begin(),
                   block_hash.begin() + std::min(block_hash.size(), size_t(255)));

        // timestamp (8 bytes LE)
        for (int i = 0; i < 8; ++i) out.push_back((timestamp >> (8*i)) & 0xff);

        // status (1 byte)
        out.push_back(status);

        return out;
    }

    static TheCheckpoint deserialize(const std::vector<uint8_t>& data) {
        TheCheckpoint cp;
        if (data.size() < 50) return cp;
        size_t pos = 0;

        uint8_t ver = data[pos++];
        if (ver != 0x01) return cp;

        // state_root
        if (pos + 32 > data.size()) return cp;
        std::memcpy(cp.the_state_root.data(), &data[pos], 32);
        pos += 32;

        // sharechain_height
        if (pos + 4 > data.size()) return cp;
        cp.sharechain_height = data[pos] | (data[pos+1]<<8) | (data[pos+2]<<16) | (data[pos+3]<<24);
        pos += 4;

        // miner_count
        if (pos + 2 > data.size()) return cp;
        cp.miner_count = data[pos] | (data[pos+1]<<8);
        pos += 2;

        // hashrate_class
        if (pos >= data.size()) return cp;
        cp.hashrate_class = data[pos++];

        // chain
        if (pos >= data.size()) return cp;
        uint8_t clen = data[pos++];
        if (pos + clen > data.size()) return cp;
        cp.chain = std::string(reinterpret_cast<const char*>(&data[pos]), clen);
        pos += clen;

        // block_height
        if (pos + 8 > data.size()) return cp;
        cp.block_height = 0;
        for (int i = 0; i < 8; ++i) cp.block_height |= uint64_t(data[pos+i]) << (8*i);
        pos += 8;

        // block_hash
        if (pos >= data.size()) return cp;
        uint8_t hlen = data[pos++];
        if (pos + hlen > data.size()) return cp;
        cp.block_hash = std::string(reinterpret_cast<const char*>(&data[pos]), hlen);
        pos += hlen;

        // timestamp
        if (pos + 8 > data.size()) return cp;
        cp.timestamp = 0;
        for (int i = 0; i < 8; ++i) cp.timestamp |= uint64_t(data[pos+i]) << (8*i);
        pos += 8;

        // status
        if (pos < data.size()) cp.status = data[pos++];

        return cp;
    }
};

/// Persistent THE checkpoint store — never pruned
class TheCheckpointStore {
public:
    explicit TheCheckpointStore(core::LevelDBStore& store) : m_store(store) {}

    /// Store a new checkpoint
    bool store(const TheCheckpoint& cp) {
        auto key = make_key(cp.chain, cp.block_height);
        return m_store.put(key, cp.serialize());
    }

    /// Update checkpoint status after verification
    bool update_status(const std::string& chain, uint64_t block_height, uint8_t new_status) {
        auto key = make_key(chain, block_height);
        std::vector<uint8_t> data;
        if (!m_store.get(key, data)) return false;
        auto cp = TheCheckpoint::deserialize(data);
        cp.status = new_status;
        return m_store.put(key, cp.serialize());
    }

    /// Get the latest verified checkpoint for a chain
    std::optional<TheCheckpoint> get_latest_verified(const std::string& chain) {
        auto keys = m_store.list_keys("thecp:" + chain + ":", 1000);
        // Keys are sorted lexicographically; height is zero-padded, so last = newest
        for (auto it = keys.rbegin(); it != keys.rend(); ++it) {
            std::vector<uint8_t> data;
            if (m_store.get(*it, data)) {
                auto cp = TheCheckpoint::deserialize(data);
                if (cp.status == 1) // verified
                    return cp;
            }
        }
        return std::nullopt;
    }

    /// Get the latest checkpoint (any status)
    std::optional<TheCheckpoint> get_latest(const std::string& chain) {
        auto keys = m_store.list_keys("thecp:" + chain + ":", 1000);
        if (keys.empty()) return std::nullopt;
        std::vector<uint8_t> data;
        if (m_store.get(keys.back(), data)) {
            return TheCheckpoint::deserialize(data);
        }
        return std::nullopt;
    }

    /// Load all checkpoints for a chain
    std::vector<TheCheckpoint> load_all(const std::string& chain = "") {
        std::string prefix = chain.empty() ? "thecp:" : ("thecp:" + chain + ":");
        auto keys = m_store.list_keys(prefix, 10000);
        std::vector<TheCheckpoint> result;
        for (const auto& key : keys) {
            std::vector<uint8_t> data;
            if (m_store.get(key, data)) {
                auto cp = TheCheckpoint::deserialize(data);
                if (!cp.block_hash.empty())
                    result.push_back(std::move(cp));
            }
        }
        return result;
    }

    size_t count() {
        return m_store.list_keys("thecp:", 10000).size();
    }

private:
    core::LevelDBStore& m_store;

    static std::string make_key(const std::string& chain, uint64_t height) {
        std::ostringstream oss;
        oss << "thecp:" << chain << ":"
            << std::setfill('0') << std::setw(12) << height;
        return oss.str();
    }
};

} // namespace storage
} // namespace c2pool
