#pragma once

/// BCH Mempool — Phase 2 + UTXO fee computation
///
/// In-memory transaction pool receiving transactions from P2P peers.
/// When a UTXOViewCache is available, computes per-transaction fees
/// (sum_inputs - sum_outputs) and maintains a feerate-sorted index
/// for optimal block template building.
///
/// BCH divergences from the BTC/LTC source (see transaction.hpp banner):
///  - No SegWit: transactions have no witness data. There is no BIP141
///    weight and no vsize. Block/template budgeting is in raw BYTES, and
///    feerate is sat/byte (not sat/vbyte). MempoolEntry tracks `byte_size`
///    only — `weight`/`witness_size` are removed, not zeroed.
///  - txid = SHA256d of the (only) legacy serialization. wtxid == txid;
///    BCH has no separate witness txid. all_txs_map_wtxid() is retained
///    purely for the compact-block call site and is identical to
///    all_txs_map() — BCH BIP152 short IDs are computed over the txid.
///
/// Thread-safe via internal mutex.

#include "block.hpp"
#include "transaction.hpp"

#include <core/uint256.hpp>
#include <core/pack.hpp>
#include <core/hash.hpp>
#include <core/log.hpp>
#include <core/coin/utxo_view_cache.hpp>

#include <algorithm>
#include <atomic>
#include <limits>
#include <map>
#include <mutex>
#include <set>
#include <vector>
#include <ctime>
#include <cstdint>
#include <optional>

namespace bch {
namespace coin {

/// BCH money/maturity limits.
/// 21M * 1e8 sat max value, 100-block coinbase maturity, no pegout (no MWEB).
/// Defined coin-local (not in core/coin/utxo.hpp) to keep the BCH module off
/// the shared-base path — BCH is standalone parent in V36.
/// Reference: bitcoin-cash-node/src/consensus/amount.h MAX_MONEY,
///            bitcoin-cash-node/src/consensus/consensus.h COINBASE_MATURITY
static constexpr core::coin::ChainLimits BCH_LIMITS = {2'100'000'000'000'000LL, 100, 0};

// ─── MempoolEntry ────────────────────────────────────────────────────────────

struct MempoolEntry {
    MutableTransaction tx;
    uint256  txid;
    uint32_t byte_size{0};      // serialized bytes (BCH has a single, witness-free encoding)
    uint64_t fee{0};            // satoshi (computed from UTXO when available)
    bool     fee_known{false};  // true when fee was computed from UTXO lookups
    time_t   time_added{0};

    /// Feerate in sat/byte (BCH has no vsize — block budget is raw bytes).
    double feerate() const {
        return (fee_known && byte_size > 0) ? static_cast<double>(fee) / byte_size : 0.0;
    }
};

// ─── Helpers ─────────────────────────────────────────────────────────────────

/// Compute txid = SHA256d of the BCH (witness-free) serialization.
/// wtxid == txid in BCH; there is no separate witness serialization.
inline uint256 compute_txid(const MutableTransaction& tx) {
    auto packed = pack(tx);
    return Hash(packed.get_span());
}

/// Compute the serialized byte size of a transaction (BCH block budget unit).
inline uint32_t compute_tx_byte_size(const MutableTransaction& tx) {
    return static_cast<uint32_t>(pack(tx).size());
}

// ─── Mempool ─────────────────────────────────────────────────────────────────

class Mempool {
public:
    /// Maximum total bytes (serialized) in the pool.
    static constexpr size_t DEFAULT_MAX_BYTES = 300ULL * 1024 * 1024;  // 300 MB

    /// Transaction expiry window.
    static constexpr time_t DEFAULT_EXPIRY_SECS = 14 * 24 * 3600;  // 14 days

    explicit Mempool(core::coin::ChainLimits limits = BCH_LIMITS,
                     size_t max_bytes  = DEFAULT_MAX_BYTES,
                     time_t expiry_sec = DEFAULT_EXPIRY_SECS)
        : m_limits(limits)
        , m_max_bytes(max_bytes)
        , m_expiry_sec(expiry_sec)
    {}

    /// Update the current chain tip height (for coinbase maturity checks).
    /// Call after each block connection.
    void set_tip_height(uint32_t h) { m_tip_height = h; }
    void set_utxo(core::coin::UTXOViewCache* u) { m_utxo.store(u); }

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
        entry.tx        = tx;
        entry.txid      = txid;
        entry.byte_size = compute_tx_byte_size(tx);
        entry.time_added = std::time(nullptr);

        // Compute fee from UTXO + mempool parent lookups
        compute_fee_locked(entry, utxo);

        // Enforce size cap: evict oldest entries until we have room
        int evicted = 0;
        while (m_total_bytes + entry.byte_size > m_max_bytes && !m_time_index.empty()) {
            auto oldest = m_time_index.begin();
            evict_one_locked(oldest->second);
            ++evicted;
        }

        m_pool[txid] = std::move(entry);
        auto& stored = m_pool[txid];
        m_time_index.emplace(stored.time_added, txid);
        m_total_bytes += stored.byte_size;

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
            LOG_INFO << "[EMB-BCH] Mempool: size=" << m_pool.size()
                     << " bytes=" << m_total_bytes << "/" << m_max_bytes
                     << " txid=" << txid.GetHex().substr(0, 16)
                     << " sz=" << stored.byte_size
                     << " fee=" << (stored.fee_known ? std::to_string(stored.fee) : "?")
                     << (evicted > 0 ? " evict=" + std::to_string(evicted) : "");
        }
        return true;
    }

    /// Add a transaction with a KNOWN fee supplied by an authoritative source
    /// (BCHN GBT transactions[].fee). Used by the embedded-daemon RPC mempool
    /// sync: BCHN already validated the tx and computed its exact fee, so we set
    /// fee_known=true and index it for template selection. Without this the tx
    /// lands with fee_known=false and get_sorted_txs_with_fees() excludes it
    /// (empty template -> coinbase-only won blocks, nTx=1). Fee accuracy matches
    /// p2pool, which sources fees from the same daemon GBT.
    bool add_tx_with_known_fee(const MutableTransaction& tx, uint64_t fee) {
        uint256 txid = compute_txid(tx);
        std::lock_guard<std::mutex> lock(m_mutex);
        if (m_pool.count(txid))
            return false;
        MempoolEntry entry;
        entry.tx         = tx;
        entry.txid       = txid;
        entry.byte_size  = compute_tx_byte_size(tx);
        entry.time_added = std::time(nullptr);
        entry.fee        = fee;
        entry.fee_known  = true;
        int evicted = 0;
        while (m_total_bytes + entry.byte_size > m_max_bytes && !m_time_index.empty()) {
            auto oldest = m_time_index.begin();
            evict_one_locked(oldest->second);
            ++evicted;
        }
        m_pool[txid] = std::move(entry);
        auto& stored = m_pool[txid];
        m_time_index.emplace(stored.time_added, txid);
        m_total_bytes += stored.byte_size;
        for (const auto& vin : stored.tx.vin) {
            m_spent_outputs[std::make_pair(vin.prevout.hash, vin.prevout.index)] = txid;
        }
        m_feerate_index.emplace(stored.feerate(), txid);
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
                        LOG_INFO << "[EMB-BCH] Mempool: removing conflict tx "
                                 << conflict_txid.GetHex().substr(0, 16)
                                 << " (spends same input as confirmed tx)";
                        ++conflicts;
                    }
                    remove_tx_locked(conflict_txid);
                }
            }
        }

        // Phase 3: quarantine orphaned children of conflict-removed txs.
        // When a mempool tx is removed due to double-spend conflict (Phase 2),
        // any child mempool tx that spends its outputs becomes orphaned.
        // Reference: bitcoin-cash-node txmempool.cpp removeRecursive()
        if (conflicts > 0) {
            for (auto& [txid, entry] : m_pool) {
                for (const auto& vin : entry.tx.vin) {
                    // If input references a tx no longer in mempool, the parent
                    // may have been conflict-removed. Conservatively re-mark the
                    // fee unknown so it is revalidated against the UTXO next cycle.
                    if (!m_pool.count(vin.prevout.hash) && entry.fee_known) {
                        entry.fee_known = false;
                    }
                }
            }
        }

        if (removed > 0 || conflicts > 0) {
            LOG_INFO << "[EMB-BCH] Mempool: block cleanup removed=" << removed
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

    /// Return up to max_bytes serialized bytes worth of transactions,
    /// in FIFO order (oldest first — fair ordering without feerate data).
    /// Legacy method for backward compatibility.
    ///
    /// Note: the BCH template builder is responsible for re-ordering the
    /// selected set into canonical (CTOR / lexical-txid) order; the mempool
    /// returns a selection, not a block-ready ordering.
    std::vector<MutableTransaction> get_sorted_txs(uint32_t max_bytes) const {
        std::lock_guard<std::mutex> lock(m_mutex);

        std::vector<MutableTransaction> result;
        uint32_t total_bytes = 0;

        // Iterate by arrival time (oldest first)
        for (auto& [ts, txid] : m_time_index) {
            auto it = m_pool.find(txid);
            if (it == m_pool.end()) continue;

            const auto& entry = it->second;
            if (total_bytes + entry.byte_size > max_bytes) continue;

            total_bytes += entry.byte_size;
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

    /// Return transactions sorted by feerate (highest first), up to max_bytes.
    /// Transactions with known fees are prioritized; unknown-fee txs fill remaining space.
    /// Returns total_fees across all selected transactions (known fees only).
    std::pair<std::vector<SelectedTx>, uint64_t>
    get_sorted_txs_with_fees(uint32_t max_bytes) const {
        std::lock_guard<std::mutex> lock(m_mutex);

        std::vector<SelectedTx> result;
        uint64_t total_fees = 0;
        uint32_t total_bytes = 0;
        std::set<uint256> selected;

        // Pass 1: highest feerate first (known-fee txs)
        auto* utxo = m_utxo.load();
        for (auto it = m_feerate_index.begin(); it != m_feerate_index.end(); ++it) {
            auto pit = m_pool.find(it->second);
            if (pit == m_pool.end()) continue;
            const auto& entry = pit->second;
            if (!entry.fee_known) continue;
            if (total_bytes + entry.byte_size > max_bytes) continue;

            // Guard: verify inputs still exist in UTXO (or parent mempool tx).
            // Catches stale txs in the window between tip-change and full_block arrival.
            if (utxo) {
                bool inputs_ok = true;
                for (const auto& vin : entry.tx.vin) {
                    core::coin::Outpoint op(vin.prevout.hash, vin.prevout.index);
                    core::coin::Coin coin;
                    if (!utxo->get_coin(op, coin)) {
                        // Check if parent is in mempool (CPFP chain)
                        if (!m_pool.count(vin.prevout.hash) ||
                            vin.prevout.index >= m_pool.at(vin.prevout.hash).tx.vout.size()) {
                            inputs_ok = false;
                            break;
                        }
                    }
                }
                if (!inputs_ok) continue;  // skip stale tx
            }

            total_bytes += entry.byte_size;
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
            LOG_INFO << "[EMB-BCH] Mempool fee revalidation: resolved=" << resolved
                     << " still_unknown=" << still_unknown
                     << " resolved_fees=" << resolved_total_fee << " sat"
                     << " pool_size=" << m_pool.size();
        }
        return resolved;
    }

    /// Re-validate all fee-known mempool transactions against the UTXO set.
    /// Evicts any transaction whose inputs are no longer in the UTXO set
    /// (i.e., were spent by a confirmed block but not caught by remove_for_block's
    /// conflict detection — e.g., when the spending tx wasn't tracked in m_spent_outputs).
    /// Call after remove_for_block() + UTXO connect to catch stale transactions.
    /// Returns the number of evicted transactions.
    int revalidate_inputs(core::coin::UTXOViewCache* utxo) {
        if (!utxo) return 0;
        std::lock_guard<std::mutex> lock(m_mutex);

        std::vector<uint256> to_remove;
        for (const auto& [txid, entry] : m_pool) {
            if (!entry.fee_known) continue;  // already quarantined
            for (const auto& vin : entry.tx.vin) {
                core::coin::Outpoint op(vin.prevout.hash, vin.prevout.index);
                core::coin::Coin coin;
                if (!utxo->get_coin(op, coin)) {
                    // Input not in UTXO — check if parent is in mempool (CPFP)
                    if (m_pool.count(vin.prevout.hash) &&
                        vin.prevout.index < m_pool.at(vin.prevout.hash).tx.vout.size())
                        continue;  // parent still in mempool, tx is valid
                    to_remove.push_back(txid);
                    break;
                }
            }
        }

        for (const auto& txid : to_remove)
            remove_tx_locked(txid);

        if (!to_remove.empty()) {
            LOG_INFO << "[EMB-BCH] Mempool revalidate: evicted " << to_remove.size()
                     << " stale txs (inputs spent), remaining=" << m_pool.size();
        }
        return static_cast<int>(to_remove.size());
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

    /// Return all transactions keyed by wtxid for compact-block reconstruction.
    /// BCH has no SegWit: wtxid == txid, so this is identical to all_txs_map().
    /// Retained under this name only to satisfy the compact-block call site;
    /// BCH BIP152 short IDs are derived from the txid.
    std::map<uint256, MutableTransaction> all_txs_map_wtxid() const {
        return all_txs_map();
    }

    // ─── Lightweight snapshot for explorer API ───────────────────────────

    /// Lightweight entry metadata (no MutableTransaction copy).
    struct MempoolEntrySummary {
        uint256  txid;
        uint32_t byte_size{0};
        uint64_t fee{0};
        bool     fee_known{false};
        time_t   time_added{0};
        uint32_t n_vin{0};
        uint32_t n_vout{0};
        double feerate() const {
            return (fee_known && byte_size > 0) ? static_cast<double>(fee) / byte_size : 0.0;
        }
    };

    /// Aggregate mempool statistics + sorted entry list.
    struct MempoolSummary {
        size_t   tx_count{0};
        size_t   total_bytes{0};
        uint64_t total_fees{0};
        size_t   fee_known_count{0};
        double   min_feerate{0};
        double   max_feerate{0};
        double   median_feerate{0};
        double   avg_feerate{0};
        time_t   oldest_time{0};
        std::vector<MempoolEntrySummary> entries;  // sorted by feerate descending
    };

    /// Build a lightweight snapshot: copies only metadata (no tx bodies),
    /// computes aggregates, sorts by feerate descending.  Single lock hold.
    MempoolSummary get_summary() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        MempoolSummary s;
        s.tx_count = m_pool.size();
        s.total_bytes = m_total_bytes;
        s.entries.reserve(m_pool.size());

        std::vector<double> feerates;  // for median computation
        double feerate_sum = 0;
        s.oldest_time = std::numeric_limits<time_t>::max();

        for (const auto& [id, e] : m_pool) {
            MempoolEntrySummary es;
            es.txid       = e.txid;
            es.byte_size  = e.byte_size;
            es.fee        = e.fee;
            es.fee_known  = e.fee_known;
            es.time_added = e.time_added;
            es.n_vin      = static_cast<uint32_t>(e.tx.vin.size());
            es.n_vout     = static_cast<uint32_t>(e.tx.vout.size());
            if (e.fee_known) {
                s.total_fees += e.fee;
                ++s.fee_known_count;
                double fr = es.feerate();
                feerates.push_back(fr);
                feerate_sum += fr;
                if (fr < s.min_feerate || s.min_feerate == 0) s.min_feerate = fr;
                if (fr > s.max_feerate) s.max_feerate = fr;
            }
            if (e.time_added < s.oldest_time) s.oldest_time = e.time_added;
            s.entries.push_back(std::move(es));
        }

        // Sort by feerate descending
        std::sort(s.entries.begin(), s.entries.end(),
            [](const MempoolEntrySummary& a, const MempoolEntrySummary& b) {
                return a.feerate() > b.feerate();
            });

        // Median + average feerate
        if (!feerates.empty()) {
            std::sort(feerates.begin(), feerates.end());
            s.median_feerate = feerates[feerates.size() / 2];
            s.avg_feerate = feerate_sum / feerates.size();
        }
        if (s.tx_count == 0) s.oldest_time = 0;

        return s;
    }

private:
    // ─── Internal (caller holds mutex) ───────────────────────────────────

    /// Compute fee for a mempool entry using UTXO + parent mempool lookups.
    /// Includes MoneyRange overflow checks and coinbase maturity.
    /// Reference: bitcoin-cash-node consensus/tx_verify.cpp CheckTxInputs()
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
                // Coinbase maturity check
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

        m_total_bytes -= it->second.byte_size;

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

    /// Feerate index: feerate (sat/byte, descending) → txid.
    /// Only contains entries with fee_known=true.
    /// Used by get_sorted_txs_with_fees() for optimal block template building.
    std::multimap<double, uint256, std::greater<double>> m_feerate_index;

    /// Conflict detection: (prev_txid, prev_n) → spending mempool txid.
    /// Mirrors Bitcoin Cash Node's mapNextTx for O(1) double-spend detection.
    std::map<std::pair<uint256, uint32_t>, uint256> m_spent_outputs;

    size_t m_total_bytes{0};    // sum of byte_size across all entries
    size_t m_max_bytes;
    time_t m_expiry_sec;
    core::coin::ChainLimits m_limits;   // MoneyRange + maturity constants
    uint32_t m_tip_height{0};           // current chain tip (for maturity checks)
    std::atomic<core::coin::UTXOViewCache*> m_utxo{nullptr};  // for template-time input validation
};

} // namespace coin
} // namespace bch
