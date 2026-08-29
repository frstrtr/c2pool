// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

/// Phase C-TEMPLATE step 13b: persistent CreditPool state.
///
/// Schema (single 'B' key — the pool is just one int64, no per-entry
/// table needed unlike SMLDb / QuorumDb / MnStateDb):
///   key = "B"
///   value = [32B block_hash] [4B LE height] [8B LE int64 balance]
///                                                     [1B initialized flag]
///
/// On open(), load the value if present. On every successful
/// CreditPool::apply_block() in main_dash, write the new state.
///
/// Sentinel cross-check on startup: best_hash must match SMLDb's.
/// On mismatch, the credit pool is wiped and re-seeds from the next
/// observed CCbTx (same fail-safe pattern as the other dbs).

#include <core/leveldb_store.hpp>
#include <core/uint256.hpp>
#include <core/log.hpp>

#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

namespace dash {
namespace coin {

class CreditPoolDb
{
public:
    explicit CreditPoolDb(const std::string& db_path,
                          const ::core::LevelDBOptions& opts = {})
        : m_store(db_path, opts) {}

    bool open()
    {
        if (!m_store.open()) return false;
        load_state();
        LOG_INFO << "[CP-DB] opened best_height=" << m_best_height
                 << " best_hash=" << m_best_hash.GetHex().substr(0, 16)
                 << " balance=" << m_balance
                 << " initialized=" << (m_initialized ? "yes" : "no");
        return true;
    }

    void close() { m_store.close(); }
    bool is_open() const { return m_store.is_open(); }

    uint256  get_best_hash() const   { return m_best_hash; }
    uint32_t get_best_height() const { return m_best_height; }
    int64_t  get_balance() const     { return m_balance; }
    bool     is_initialized() const  { return m_initialized; }

    // Atomic write of the full state.
    bool write_state(const uint256& best_hash,
                     uint32_t       best_height,
                     int64_t        balance,
                     bool           initialized)
    {
        auto batch = m_store.create_batch();
        batch.put(make_state_key(),
                  encode_state(best_hash, best_height, balance, initialized));
        if (!batch.commit()) {
            LOG_WARNING << "[CP-DB] write_state batch commit failed";
            return false;
        }
        m_best_hash   = best_hash;
        m_best_height = best_height;
        m_balance     = balance;
        m_initialized = initialized;
        return true;
    }

    bool clear()
    {
        auto batch = m_store.create_batch();
        batch.remove(make_state_key());
        if (!batch.commit()) return false;
        m_best_hash   = uint256{};
        m_best_height = 0;
        m_balance     = 0;
        m_initialized = false;
        LOG_INFO << "[CP-DB] cleared";
        return true;
    }

private:
    ::core::LevelDBStore m_store;
    uint256              m_best_hash;
    uint32_t             m_best_height{0};
    int64_t              m_balance{0};
    bool                 m_initialized{false};

    static std::string make_state_key() { return std::string(1, 'B'); }

    static std::vector<uint8_t> encode_state(const uint256& hash,
                                             uint32_t       height,
                                             int64_t        balance,
                                             bool           initialized)
    {
        std::vector<uint8_t> out(45);
        std::memcpy(out.data(), hash.data(), 32);
        out[32] = static_cast<uint8_t>( height        & 0xFF);
        out[33] = static_cast<uint8_t>((height >>  8) & 0xFF);
        out[34] = static_cast<uint8_t>((height >> 16) & 0xFF);
        out[35] = static_cast<uint8_t>((height >> 24) & 0xFF);
        uint64_t u = static_cast<uint64_t>(balance);
        for (int i = 0; i < 8; ++i)
            out[36 + i] = static_cast<uint8_t>((u >> (8 * i)) & 0xFF);
        out[44] = initialized ? 1 : 0;
        return out;
    }

    void load_state()
    {
        std::vector<uint8_t> data;
        if (!m_store.get(make_state_key(), data) || data.size() < 45) {
            return;
        }
        std::memcpy(m_best_hash.data(), data.data(), 32);
        m_best_height = uint32_t(data[32])
                      | (uint32_t(data[33]) <<  8)
                      | (uint32_t(data[34]) << 16)
                      | (uint32_t(data[35]) << 24);
        uint64_t u = 0;
        for (int i = 0; i < 8; ++i)
            u |= uint64_t(data[36 + i]) << (8 * i);
        m_balance     = static_cast<int64_t>(u);
        m_initialized = data[44] != 0;
    }
};

} // namespace coin
} // namespace dash