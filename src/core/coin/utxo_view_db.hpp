#pragma once

/// UTXOViewDB: LevelDB-backed persistent UTXO store.
///
/// Stores unspent transaction outputs (coins) in LevelDB with atomic
/// batch writes for crash-safe block connection/disconnection.
///
/// Key schema:
///   'C' + txid(32B) + index(4B LE)  →  serialized Coin
///   'B'                              →  best_block_hash(32B) + height(4B LE)
///   'U' + height(4B BE)             →  serialized BlockUndo
///
/// Reference: Litecoin Core txdb.h CCoinsViewDB

#include "utxo.hpp"

#include <core/leveldb_store.hpp>
#include <core/uint256.hpp>
#include <core/log.hpp>

#include <cstdint>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

namespace core {
namespace coin {

class UTXOViewDB {
public:
    explicit UTXOViewDB(const std::string& db_path,
                        const LevelDBOptions& opts = {})
        : m_store(db_path, opts)
    {}

    /// Open the database. Must be called before any other operation.
    bool open() {
        if (!m_store.open())
            return false;
        // Load best block state
        load_best_block();
        LOG_INFO << "[UTXO-DB] opened at " << m_store.is_open()
                 << " best_height=" << m_best_height
                 << " best_block=" << m_best_block.GetHex().substr(0, 16);
        return true;
    }

    void close() { m_store.close(); }
    bool is_open() const { return m_store.is_open(); }

    // ── Single-coin access ──────────────────────────────────────────────

    /// Retrieve a coin by outpoint. Returns false if not found.
    bool get_coin(const Outpoint& op, Coin& coin) {
        auto key = make_coin_key(op);
        std::vector<uint8_t> data;
        if (!m_store.get(key, data))
            return false;
        return deserialize_coin(data, coin);
    }

    /// Check if a coin exists.
    bool have_coin(const Outpoint& op) {
        auto key = make_coin_key(op);
        return m_store.exists(key);
    }

    // ── Best block state ────────────────────────────────────────────────

    uint256 get_best_block() const { return m_best_block; }
    uint32_t get_best_height() const { return m_best_height; }

    // ── Batch write (atomic block connection) ───────────────────────────

    /// Flags for coin changes:
    ///   - Coin present in optional → add/update
    ///   - nullopt → erase (spent)
    using CoinChange = std::optional<Coin>;
    using ChangeMap = std::unordered_map<Outpoint, CoinChange, OutpointHasher>;

    /// Atomically apply a batch of coin changes and update best block.
    /// This is called once per block connection or disconnection.
    bool write_batch(const ChangeMap& changes,
                     const uint256& best_block,
                     uint32_t best_height) {
        auto batch = m_store.create_batch();

        for (const auto& [op, change] : changes) {
            auto key = make_coin_key(op);
            if (change.has_value()) {
                // Add/update coin
                auto data = serialize_coin(*change);
                batch.put(key, data);
            } else {
                // Erase spent coin
                batch.remove(key);
            }
        }

        // Update best block
        {
            std::vector<uint8_t> state_data;
            state_data.resize(36);
            std::memcpy(state_data.data(), best_block.data(), 32);
            state_data[32] = best_height & 0xFF;
            state_data[33] = (best_height >> 8) & 0xFF;
            state_data[34] = (best_height >> 16) & 0xFF;
            state_data[35] = (best_height >> 24) & 0xFF;
            batch.put(make_state_key(), state_data);
        }

        if (!batch.commit())
            return false;

        m_best_block = best_block;
        m_best_height = best_height;
        return true;
    }

    // ── Block undo data ─────────────────────────────────────────────────

    /// Store undo data for a block at given height.
    bool put_block_undo(uint32_t height, const BlockUndo& undo) {
        auto key = make_undo_key(height);
        auto data = serialize_block_undo(undo);
        return m_store.put(key, data);
    }

    /// Retrieve undo data for a block at given height.
    bool get_block_undo(uint32_t height, BlockUndo& undo) {
        auto key = make_undo_key(height);
        std::vector<uint8_t> data;
        if (!m_store.get(key, data))
            return false;
        return deserialize_block_undo(data, undo);
    }

    /// Remove undo data for a block (after successful disconnect or pruning).
    bool remove_block_undo(uint32_t height) {
        auto key = make_undo_key(height);
        return m_store.remove(key);
    }

private:
    LevelDBStore m_store;
    uint256  m_best_block;
    uint32_t m_best_height{0};

    // ── Key construction ────────────────────────────────────────────────

    static std::string make_coin_key(const Outpoint& op) {
        std::string key;
        key.reserve(37);  // 'C' + 32 + 4
        key.push_back('C');
        key.append(outpoint_to_key(op));
        return key;
    }

    static std::string make_state_key() {
        return std::string(1, 'B');
    }

    static std::string make_undo_key(uint32_t height) {
        std::string key;
        key.reserve(5);  // 'U' + 4 bytes (big-endian for sorted iteration)
        key.push_back('U');
        key.push_back(static_cast<char>((height >> 24) & 0xFF));
        key.push_back(static_cast<char>((height >> 16) & 0xFF));
        key.push_back(static_cast<char>((height >> 8) & 0xFF));
        key.push_back(static_cast<char>(height & 0xFF));
        return key;
    }

    void load_best_block() {
        std::vector<uint8_t> data;
        if (m_store.get(make_state_key(), data) && data.size() >= 36) {
            std::memcpy(m_best_block.data(), data.data(), 32);
            m_best_height = uint32_t(data[32]) | (uint32_t(data[33]) << 8)
                          | (uint32_t(data[34]) << 16) | (uint32_t(data[35]) << 24);
        }
    }
};

} // namespace coin
} // namespace core
