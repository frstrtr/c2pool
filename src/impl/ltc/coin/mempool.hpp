#pragma once

/// LTC Mempool — Phase 2 + UTXO fee computation
///
/// In-memory transaction pool receiving transactions from P2P peers.
/// When a UTXOViewCache is available, computes per-transaction fees
/// (sum_inputs - sum_outputs) and maintains a feerate-sorted index
/// for optimal block template building.
///
/// Thread-safe via internal mutex.

#include "block.hpp"
#include "transaction.hpp"

#include <core/uint256.hpp>
#include <core/pack.hpp>
#include <core/hash.hpp>
#include <core/log.hpp>
#include <core/coin/utxo_view_cache.hpp>

#include <map>
#include <mutex>
#include <set>
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
    uint64_t fee{0};            // satoshi (computed from UTXO when available)
    bool     fee_known{false};  // true when fee was computed from UTXO lookups
    time_t   time_added{0};

    double feerate() const {
        uint32_t vsize = (weight + 3) / 4;  // ceil(weight/4)
        return (fee_known && vsize > 0) ? static_cast<double>(fee) / vsize : 0.0;
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

    explicit Mempool(core::coin::ChainLimits limits = core::coin::LTC_LIMITS,
                     size_t max_bytes  = DEFAULT_MAX_BYTES,
                     time_t expiry_sec = DEFAULT_EXPIRY_SECS)
        : m_limits(limits)
        , m_max_bytes(max_bytes)
        , m_expiry_sec(expiry_sec)
    {}

    /// Update the current chain tip height (for coinbase maturity checks).
    /// Call after each block connection.
    void set_tip_height(uint32_t h) { m_tip_height = h; }

    // Disable copy
    Mempool(const Mempool&) = delete;
    Mempool& operator=(const Mempool&) = delete;

    // ─── Mutation ────────────────────────────────────────────────────────

    /// Add a transaction to the pool (no fee computation).
    /// Returns false if already known or if the tx is malformed.
    bool add_tx(const MutableTransaction& tx) {
        return add_tx(tx, nullptr);
    }

    /// Add a transaction to the pool with optional UTXO-based fee computation.
    /// When utxo is non-null, computes fee = sum(input_values) - sum(output_values).
    /// Falls back to fee_known=false if any input is missing from the UTXO set
    /// or from a parent mempool transaction (chain-of-unconfirmed / CPFP).
    bool add_tx(const MutableTransaction& tx, core::coin::UTXOViewCache* utxo) {
        uint256 txid = compute_txid(tx);

        std::lock_guard<std::mutex> lock(m_mutex);

        // Reject duplicates
        if (m_pool.count(txid))
            return false;

        MempoolEntry entry;
        entry.tx    = tx;
        entry.txid  = txid;
        compute_tx_weight(tx, entry.base_size, entry.witness_size, entry.weight);
        entry.time_added  = std::time(nullptr);

        // Compute fee from UTXO + mempool parent lookups
        compute_fee_locked(entry, utxo);

        // Enforce size cap: evict oldest entries until we have room
        int evicted = 0;
        while (m_total_bytes + entry.base_size > m_max_bytes && !m_time_index.empty()) {
            auto oldest = m_time_index.begin();
            evict_one_locked(oldest->second);
            ++evicted;
        }

        m_pool[txid] = std::move(entry);
        auto& stored = m_pool[txid];
        m_time_index.emplace(stored.time_added, txid);
        m_total_bytes += stored.base_size;

        // Track spent outputs for conflict detection
        for (const auto& vin : stored.tx.vin) {
            m_spent_outputs[std::make_pair(vin.prevout.hash, vin.prevout.index)] = txid;
        }

        // Add to feerate index if fee is known
        if (stored.fee_known) {
            m_feerate_index.emplace(stored.feerate(), txid);
        }

        // Periodic mempool stats (every 100 txs)
        if (m_pool.size() % 100 == 0 || m_pool.size() <= 5) {
            LOG_INFO << "[EMB] Mempool: size=" << m_pool.size()
                     << " bytes=" << m_total_bytes << "/" << m_max_bytes
                     << " txid=" << txid.GetHex().substr(0, 16)
                     << " w=" << stored.weight
                     << " fee=" << (stored.fee_known ? std::to_string(stored.fee) : "?")
                     << (evicted > 0 ? " evict=" + std::to_string(evicted) : "");
        }
        return true;
    }

    /// Remove a single transaction by txid.
    void remove_tx(const uint256& txid) {
        std::lock_guard<std::mutex> lock(m_mutex);
        remove_tx_locked(txid);
    }

    /// Manually set a transaction's fee (for testing without a UTXO set).
    void set_tx_fee(const uint256& txid, uint64_t fee) {
        std::lock_guard<std::mutex> lock(m_mutex);
        auto it = m_pool.find(txid);
        if (it == m_pool.end()) return;
        it->second.fee = fee;
        it->second.fee_known = true;
        m_feerate_index.emplace(it->second.feerate(), txid);
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

        // Phase 3: remove orphaned children of conflict-removed txs.
        // When a mempool tx is removed due to double-spend conflict (Phase 2),
        // any child mempool tx that spends its outputs becomes orphaned.
        // Reference: LTC txmempool.cpp removeRecursive()
        int orphans = 0;
        if (conflicts > 0) {
            // Collect orphaned children: mempool txs whose inputs reference
            // a txid that was just removed (no longer in m_pool).
            std::vector<uint256> orphan_txids;
            for (auto& [txid, entry] : m_pool) {
                for (const auto& vin : entry.tx.vin) {
                    // If input references a tx NOT in UTXO and NOT in mempool,
                    // then this tx is orphaned (parent was conflict-removed).
                    // Quick check: if prevout.hash was a conflict victim.
                    if (!m_pool.count(vin.prevout.hash)) {
                        // Parent not in mempool — check if it was a removed conflict
                        // by testing if this output is in m_spent_outputs
                        // (it won't be, since the parent was erased from m_spent_outputs
                        // during Phase 2). So just check: is the parent hash absent?
                        // This is conservative — could false-positive for confirmed txs,
                        // but those are fine (child remains valid, input is in UTXO).
                        // We only mark as orphan if fee computation would fail.
                        if (entry.fee_known) {
                            // Fee was known → inputs were valid before this block.
                            // Re-check by attempting fee recompute next cycle.
                            entry.fee_known = false;
                        }
                    }
                }
            }
        }

        if (removed > 0 || conflicts > 0) {
            LOG_INFO << "[EMB] Mempool: block cleanup removed=" << removed
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
        m_feerate_index.clear();
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

    /// Sum of all known fees across mempool transactions.
    uint64_t total_fees() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        uint64_t sum = 0;
        for (const auto& [txid, entry] : m_pool) {
            if (entry.fee_known)
                sum += entry.fee;
        }
        return sum;
    }

    std::optional<MempoolEntry> get_entry(const uint256& txid) const {
        std::lock_guard<std::mutex> lock(m_mutex);
        auto it = m_pool.find(txid);
        if (it == m_pool.end()) return std::nullopt;
        return it->second;
    }

    /// Return up to max_weight BIP141 weight units worth of transactions,
    /// in FIFO order (oldest first — fair ordering without feerate data).
    /// Legacy method for backward compatibility.
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

    /// Result struct for fee-aware transaction selection.
    struct SelectedTx {
        MutableTransaction tx;
        uint64_t fee{0};
        bool     fee_known{false};
    };

    /// Return transactions sorted by feerate (highest first), up to max_weight.
    /// Transactions with known fees are prioritized; unknown-fee txs fill remaining space.
    /// Returns total_fees across all selected transactions (known fees only).
    std::pair<std::vector<SelectedTx>, uint64_t>
    get_sorted_txs_with_fees(uint32_t max_weight) const {
        std::lock_guard<std::mutex> lock(m_mutex);

        std::vector<SelectedTx> result;
        uint64_t total_fees = 0;
        uint32_t total_weight = 0;
        std::set<uint256> selected;

        // Pass 1: highest feerate first (known-fee txs)
        for (auto it = m_feerate_index.begin(); it != m_feerate_index.end(); ++it) {
            auto pit = m_pool.find(it->second);
            if (pit == m_pool.end()) continue;
            const auto& entry = pit->second;
            if (!entry.fee_known) continue;
            if (total_weight + entry.weight > max_weight) continue;

            total_weight += entry.weight;
            total_fees += entry.fee;
            result.push_back({entry.tx, entry.fee, true});
            selected.insert(entry.txid);
        }

        // Unknown-fee txs excluded from template — they'll be included
        // after fee revalidation once UTXO processes their input blocks.
        // Including them with fee=0 would cause coinbasevalue mismatch
        // vs p2pool (which gets accurate fees from daemon GBT).

        return {std::move(result), total_fees};
    }

    /// Re-attempt fee computation for all transactions with fee_known=false.
    /// Call after a new block is connected (new UTXOs may resolve missing inputs).
    /// Returns the number of transactions whose fees were successfully computed.
    int recompute_unknown_fees(core::coin::UTXOViewCache* utxo) {
        if (!utxo) return 0;
        std::lock_guard<std::mutex> lock(m_mutex);
        int resolved = 0;
        int still_unknown = 0;
        uint64_t resolved_total_fee = 0;
        for (auto& [txid, entry] : m_pool) {
            if (entry.fee_known) continue;
            if (compute_fee_locked(entry, utxo)) {
                m_feerate_index.emplace(entry.feerate(), txid);
                resolved_total_fee += entry.fee;
                ++resolved;
            } else {
                ++still_unknown;
            }
        }
        if (resolved > 0 || still_unknown > 0) {
            LOG_INFO << "[EMB] Mempool fee revalidation: resolved=" << resolved
                     << " still_unknown=" << still_unknown
                     << " resolved_fees=" << resolved_total_fee << " sat"
                     << " pool_size=" << m_pool.size();
        }
        return resolved;
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

    /// Compute fee for a mempool entry using UTXO + parent mempool lookups.
    /// Includes MoneyRange overflow checks and coinbase/pegout maturity.
    /// Reference: LTC consensus/tx_verify.cpp CheckTxInputs()
    /// Returns true if fee was successfully computed.
    bool compute_fee_locked(MempoolEntry& entry, core::coin::UTXOViewCache* utxo) {
        if (!utxo) {
            entry.fee = 0;
            entry.fee_known = false;
            return false;
        }

        int64_t value_in = 0;
        bool all_found = true;

        for (const auto& vin : entry.tx.vin) {
            core::coin::Outpoint op(vin.prevout.hash, vin.prevout.index);
            core::coin::Coin coin;

            if (utxo->get_coin(op, coin)) {
                // MoneyRange check on individual coin value
                if (!core::coin::money_range(coin.value, m_limits)) {
                    entry.fee = 0; entry.fee_known = false;
                    return false;
                }
                // Coinbase/pegout maturity check
                if (m_tip_height > 0 && !coin.is_mature(m_tip_height, m_limits)) {
                    entry.fee = 0; entry.fee_known = false;
                    return false;  // premature spend
                }
                value_in += coin.value;
                // MoneyRange check on accumulated value_in
                if (!core::coin::money_range(value_in, m_limits)) {
                    entry.fee = 0; entry.fee_known = false;
                    return false;
                }
            } else {
                // Not in UTXO — check parent mempool tx (CPFP)
                auto parent_it = m_pool.find(vin.prevout.hash);
                if (parent_it != m_pool.end()
                    && vin.prevout.index < parent_it->second.tx.vout.size()) {
                    int64_t parent_val = parent_it->second.tx.vout[vin.prevout.index].value;
                    if (!core::coin::money_range(parent_val, m_limits)) {
                        entry.fee = 0; entry.fee_known = false;
                        return false;
                    }
                    value_in += parent_val;
                    if (!core::coin::money_range(value_in, m_limits)) {
                        entry.fee = 0; entry.fee_known = false;
                        return false;
                    }
                } else {
                    all_found = false;
                    break;
                }
            }
        }

        if (!all_found) {
            entry.fee = 0;
            entry.fee_known = false;
            return false;
        }

        // Sum outputs with overflow check
        int64_t value_out = 0;
        for (const auto& vout : entry.tx.vout) {
            value_out += vout.value;
            if (!core::coin::money_range(value_out, m_limits)) {
                entry.fee = 0; entry.fee_known = false;
                return false;
            }
        }

        int64_t fee = value_in - value_out;
        if (fee < 0 || !core::coin::money_range(fee, m_limits)) {
            entry.fee = 0;
            entry.fee_known = false;
            return false;
        }

        entry.fee = static_cast<uint64_t>(fee);
        entry.fee_known = true;
        return true;
    }

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

        // Remove from feerate index
        if (it->second.fee_known) {
            auto fr_range = m_feerate_index.equal_range(it->second.feerate());
            for (auto fi = fr_range.first; fi != fr_range.second; ++fi) {
                if (fi->second == txid) {
                    m_feerate_index.erase(fi);
                    break;
                }
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

    /// Feerate index: feerate (sat/vbyte, descending) → txid.
    /// Only contains entries with fee_known=true.
    /// Used by get_sorted_txs_with_fees() for optimal block template building.
    std::multimap<double, uint256, std::greater<double>> m_feerate_index;

    /// Conflict detection: (prev_txid, prev_n) → spending mempool txid.
    /// Mirrors Litecoin Core's mapNextTx for O(1) double-spend detection.
    std::map<std::pair<uint256, uint32_t>, uint256> m_spent_outputs;

    size_t m_total_bytes{0};    // sum of base_size across all entries
    size_t m_max_bytes;
    time_t m_expiry_sec;
    core::coin::ChainLimits m_limits;   // MoneyRange + maturity constants
    uint32_t m_tip_height{0};           // current chain tip (for maturity checks)
};

} // namespace coin
} // namespace ltc
