#pragma once

/// LTC Mempool — Phase 2
///
/// In-memory transaction pool receiving transactions from P2P peers.
/// Fee computation is not possible without a UTXO set; transactions
/// are accepted unconditionally and ordered by arrival time (FIFO).
/// Weight is tracked for block template building (Phase 3).
///
/// Thread-safe via internal mutex.

#include "block.hpp"
#include "transaction.hpp"

#include <core/uint256.hpp>
#include <core/pack.hpp>
#include <core/hash.hpp>
#include <core/log.hpp>

#include <map>
#include <mutex>
#include <vector>
#include <ctime>
#include <cstdint>
#include <optional>

namespace ltc {
namespace coin {

// ─── MempoolEntry ────────────────────────────────────────────────────────────

struct MempoolEntry {
    MutableTransaction tx;
    uint256  txid;
    uint32_t base_size{0};      // legacy serialized bytes (no witness)
    uint32_t witness_size{0};   // extra bytes for witness data
    uint32_t weight{0};         // base_size*4 + witness_size  (BIP 141)
    uint64_t fee{0};            // satoshi — always 0 (no UTXO set)
    time_t   time_added{0};

    double feerate() const {
        uint32_t vsize = (weight + 3) / 4;  // ceil(weight/4)
        return vsize > 0 ? static_cast<double>(fee) / vsize : 0.0;
    }
};

// ─── Helpers ─────────────────────────────────────────────────────────────────

/// Compute txid = SHA256d of legacy (non-witness) serialization.
inline uint256 compute_txid(const MutableTransaction& tx) {
    auto packed = pack(TX_NO_WITNESS(tx));
    return Hash(packed.get_span());
}

/// Compute BIP 141 weight: base_size*4 + witness_size.
/// base_size = legacy serialized bytes; full_size = with-witness bytes.
inline void compute_tx_weight(const MutableTransaction& tx,
                               uint32_t& base_size,
                               uint32_t& witness_size,
                               uint32_t& weight)
{
    auto legacy = pack(TX_NO_WITNESS(tx));
    auto full   = pack(TX_WITH_WITNESS(tx));
    base_size    = static_cast<uint32_t>(legacy.size());
    uint32_t full_sz = static_cast<uint32_t>(full.size());
    witness_size = full_sz > base_size ? full_sz - base_size : 0;
    weight = base_size * 4 + witness_size;
}

// ─── Mempool ─────────────────────────────────────────────────────────────────

class Mempool {
public:
    /// Maximum total bytes (legacy serialized) in the pool.
    static constexpr size_t DEFAULT_MAX_BYTES = 300ULL * 1024 * 1024;  // 300 MB

    /// Transaction expiry window.
    static constexpr time_t DEFAULT_EXPIRY_SECS = 14 * 24 * 3600;  // 14 days

    explicit Mempool(size_t max_bytes  = DEFAULT_MAX_BYTES,
                     time_t expiry_sec = DEFAULT_EXPIRY_SECS)
        : m_max_bytes(max_bytes)
        , m_expiry_sec(expiry_sec)
    {}

    // Disable copy
    Mempool(const Mempool&) = delete;
    Mempool& operator=(const Mempool&) = delete;

    // ─── Mutation ────────────────────────────────────────────────────────

    /// Add a transaction to the pool.
    /// Returns false if already known or if the tx is malformed.
    bool add_tx(const MutableTransaction& tx) {
        uint256 txid = compute_txid(tx);

        std::lock_guard<std::mutex> lock(m_mutex);

        // Reject duplicates
        if (m_pool.count(txid))
            return false;

        MempoolEntry entry;
        entry.tx    = tx;
        entry.txid  = txid;
        compute_tx_weight(tx, entry.base_size, entry.witness_size, entry.weight);
        entry.fee         = 0;  // unknown — no UTXO set
        entry.time_added  = std::time(nullptr);

        // Enforce size cap: evict oldest entries until we have room
        int evicted = 0;
        while (m_total_bytes + entry.base_size > m_max_bytes && !m_time_index.empty()) {
            auto oldest = m_time_index.begin();
            evict_one_locked(oldest->second);
            ++evicted;
        }

        m_pool[txid] = std::move(entry);
        m_time_index.emplace(m_pool[txid].time_added, txid);
        m_total_bytes += m_pool[txid].base_size;

        // Track spent outputs for conflict detection (Phase 2)
        for (const auto& vin : m_pool[txid].tx.vin) {
            m_spent_outputs[std::make_pair(vin.prevout.hash, vin.prevout.index)] = txid;
        }

        // Periodic mempool stats (every 100 txs)
        if (m_pool.size() % 100 == 0 || m_pool.size() <= 5) {
            LOG_INFO << "[EMB-LTC] Mempool: size=" << m_pool.size()
                     << " bytes=" << m_total_bytes << "/" << m_max_bytes
                     << " last_txid=" << txid.GetHex().substr(0, 16)
                     << " weight=" << m_pool[txid].weight
                     << (evicted > 0 ? " evicted=" + std::to_string(evicted) : "");
        }
        return true;
    }

    /// Remove a single transaction by txid.
    void remove_tx(const uint256& txid) {
        std::lock_guard<std::mutex> lock(m_mutex);
        remove_tx_locked(txid);
    }

    /// Remove confirmed txs + double-spend conflicts from mempool.
    /// Called from the full_block callback when a new block arrives via P2P.
    ///
    /// Phase 1: remove txs whose txid appears in the block.
    /// Phase 2: remove mempool txs that spend the same outputs as block txs
    ///          (double-spend / conflict detection via m_spent_outputs).
    void remove_for_block(const BlockType& block) {
        std::lock_guard<std::mutex> lock(m_mutex);
        int removed = 0, conflicts = 0;

        // Phase 1: remove confirmed txs by txid
        for (const auto& mtx : block.m_txs) {
            uint256 txid = compute_txid(mtx);
            if (m_pool.count(txid)) ++removed;
            remove_tx_locked(txid);
        }

        // Phase 2: remove mempool txs that conflict with block txs
        // (spend the same input as a confirmed tx)
        for (const auto& mtx : block.m_txs) {
            for (const auto& vin : mtx.vin) {
                auto key = std::make_pair(vin.prevout.hash, vin.prevout.index);
                auto it = m_spent_outputs.find(key);
                if (it != m_spent_outputs.end()) {
                    // A mempool tx spends the same output — it's now invalid
                    auto conflict_txid = it->second;
                    if (m_pool.count(conflict_txid)) {
                        LOG_INFO << "[EMB-LTC] Mempool: removing conflict tx "
                                 << conflict_txid.GetHex().substr(0, 16)
                                 << " (spends same input as confirmed tx)";
                        ++conflicts;
                    }
                    remove_tx_locked(conflict_txid);
                }
            }
        }

        if (removed > 0 || conflicts > 0) {
            LOG_INFO << "[EMB-LTC] Mempool: block cleanup removed=" << removed
                     << " conflicts=" << conflicts
                     << " remaining=" << m_pool.size();
        }
    }

    /// Evict entries older than expiry_sec.
    void evict_expired() {
        time_t cutoff = std::time(nullptr) - m_expiry_sec;
        std::lock_guard<std::mutex> lock(m_mutex);
        while (!m_time_index.empty() && m_time_index.begin()->first < cutoff) {
            evict_one_locked(m_time_index.begin()->second);
        }
    }

    /// Clear the entire mempool.
    void clear() {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_pool.clear();
        m_time_index.clear();
        m_spent_outputs.clear();
        m_total_bytes = 0;
    }

    // ─── Queries ─────────────────────────────────────────────────────────

    bool contains(const uint256& txid) const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_pool.count(txid) > 0;
    }

    size_t size() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_pool.size();
    }

    size_t byte_size() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_total_bytes;
    }

    /// Sum of all known fees (always 0 without UTXO set).
    uint64_t total_fees() const { return 0; }

    std::optional<MempoolEntry> get_entry(const uint256& txid) const {
        std::lock_guard<std::mutex> lock(m_mutex);
        auto it = m_pool.find(txid);
        if (it == m_pool.end()) return std::nullopt;
        return it->second;
    }

    /// Return up to max_weight BIP141 weight units worth of transactions,
    /// in FIFO order (oldest first — fair ordering without feerate data).
    /// Caller uses this for block template building (Phase 3).
    std::vector<MutableTransaction> get_sorted_txs(uint32_t max_weight) const {
        std::lock_guard<std::mutex> lock(m_mutex);

        std::vector<MutableTransaction> result;
        uint32_t total_weight = 0;

        // Iterate by arrival time (oldest first)
        for (auto& [ts, txid] : m_time_index) {
            auto it = m_pool.find(txid);
            if (it == m_pool.end()) continue;

            const auto& entry = it->second;
            if (total_weight + entry.weight > max_weight) continue;

            total_weight += entry.weight;
            result.push_back(entry.tx);
        }
        return result;
    }

    /// Snapshot of all txids currently in the pool.
    std::vector<uint256> all_txids() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        std::vector<uint256> out;
        out.reserve(m_pool.size());
        for (auto& [txid, _] : m_pool)
            out.push_back(txid);
        return out;
    }

    /// Snapshot of all transactions as a txid→tx map (for compact block reconstruction).
    std::map<uint256, MutableTransaction> all_txs_map() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        std::map<uint256, MutableTransaction> out;
        for (const auto& [txid, entry] : m_pool)
            out[txid] = entry.tx;
        return out;
    }

private:
    // ─── Internal (caller holds mutex) ───────────────────────────────────

    void remove_tx_locked(const uint256& txid) {
        auto it = m_pool.find(txid);
        if (it == m_pool.end()) return;

        m_total_bytes -= it->second.base_size;

        // Clean up spent outputs index
        for (const auto& vin : it->second.tx.vin) {
            auto key = std::make_pair(vin.prevout.hash, vin.prevout.index);
            auto so = m_spent_outputs.find(key);
            if (so != m_spent_outputs.end() && so->second == txid)
                m_spent_outputs.erase(so);
        }

        // Remove from time index
        auto range = m_time_index.equal_range(it->second.time_added);
        for (auto ti = range.first; ti != range.second; ++ti) {
            if (ti->second == txid) {
                m_time_index.erase(ti);
                break;
            }
        }
        m_pool.erase(it);
    }

    void evict_one_locked(const uint256& txid) {
        remove_tx_locked(txid);
    }

    // ─── State ───────────────────────────────────────────────────────────

    mutable std::mutex m_mutex;

    std::map<uint256, MempoolEntry>  m_pool;        // txid → entry
    std::multimap<time_t, uint256>   m_time_index;  // arrival time → txid (FIFO)

    /// Conflict detection: (prev_txid, prev_n) → spending mempool txid.
    /// Mirrors Litecoin Core's mapNextTx for O(1) double-spend detection.
    std::map<std::pair<uint256, uint32_t>, uint256> m_spent_outputs;

    size_t m_total_bytes{0};    // sum of base_size across all entries
    size_t m_max_bytes;
    time_t m_expiry_sec;
};

} // namespace coin
} // namespace ltc
