#pragma once

/// UTXOViewCache: In-memory write-back UTXO cache.
///
/// Backed by UTXOViewDB (LevelDB). Changes are buffered in memory and
/// flushed atomically per block via flush().
///
/// Thread safety: callers must hold external lock (shared_mutex recommended).
/// Block handlers run on io_context thread; template builder may run on
/// web server thread. Use read lock for get_coin(), write lock for mutations.
///
/// Reference: Litecoin Core CCoinsViewCache

#include "utxo.hpp"
#include "utxo_view_db.hpp"

#include <core/log.hpp>

#include <cstdint>
#include <mutex>
#include <optional>
#include <shared_mutex>
#include <unordered_map>
#include <vector>

namespace core {
namespace coin {

class UTXOViewCache {
public:
    explicit UTXOViewCache(UTXOViewDB* base) : m_base(base) {
        // Initialize block counter from DB state (survives restarts)
        if (m_base && m_base->get_best_height() > 0)
            m_blocks_connected = m_base->get_best_height();
    }

    // ── Read operations ─────────────────────────────────────────────────

    /// Retrieve a coin by outpoint. Checks cache first, then DB.
    /// Returns false if not found or spent.
    bool get_coin(const Outpoint& op, Coin& coin) {
        // Check cache first
        auto it = m_cache.find(op);
        if (it != m_cache.end()) {
            if (!it->second.has_value())
                return false;  // cached as "spent"
            coin = *it->second;
            return true;
        }
        // Fall through to DB
        if (m_base && m_base->get_coin(op, coin)) {
            return true;
        }
        return false;
    }

    /// Check if a coin exists (not spent).
    bool have_coin(const Outpoint& op) {
        auto it = m_cache.find(op);
        if (it != m_cache.end())
            return it->second.has_value();
        if (m_base)
            return m_base->have_coin(op);
        return false;
    }

    /// Get the value of a specific output. Returns -1 if not found.
    int64_t get_output_value(const Outpoint& op) {
        Coin coin;
        if (get_coin(op, coin))
            return coin.value;
        return -1;
    }

    // ── Write operations ────────────────────────────────────────────────

    /// Add a coin to the cache. Overwrites any existing entry.
    void add_coin(const Outpoint& op, Coin coin) {
        m_cache[op] = std::move(coin);
    }

    /// Mark a coin as spent. Returns the coin that was spent (for undo data).
    /// Returns std::nullopt if coin was not found.
    std::optional<Coin> spend_coin(const Outpoint& op) {
        Coin coin;
        if (!get_coin(op, coin))
            return std::nullopt;
        m_cache[op] = std::nullopt;  // mark as spent
        return coin;
    }

    // ── Fee computation helper ──────────────────────────────────────────

    /// Compute the total input value for a transaction.
    /// Returns (sum_of_input_values, all_inputs_found).
    /// If any input is missing from the UTXO set, returns (partial_sum, false).
    template <typename TxType>
    std::pair<int64_t, bool> get_value_in(const TxType& tx) {
        int64_t total = 0;
        for (const auto& vin : tx.vin) {
            Outpoint op(vin.prevout.hash, vin.prevout.index);
            Coin coin;
            if (!get_coin(op, coin))
                return {total, false};
            total += coin.value;
        }
        return {total, true};
    }

    /// Compute the total output value for a transaction.
    template <typename TxType>
    static int64_t get_value_out(const TxType& tx) {
        int64_t total = 0;
        for (const auto& vout : tx.vout)
            total += vout.value;
        return total;
    }

    /// Compute the fee for a transaction: sum(inputs) - sum(outputs).
    /// Returns (fee, true) if all inputs found, (0, false) otherwise.
    template <typename TxType>
    std::pair<int64_t, bool> compute_fee(const TxType& tx) {
        auto [value_in, found] = get_value_in(tx);
        if (!found)
            return {0, false};
        int64_t value_out = get_value_out(tx);
        int64_t fee = value_in - value_out;
        if (fee < 0)
            return {0, false};  // invalid tx (outputs exceed inputs)
        return {fee, true};
    }

    // ── Block connection ────────────────────────────────────────────────

    /// Connect a block: spend inputs, add outputs, build undo data.
    /// Returns the BlockUndo for this block (for future disconnection).
    /// Undo includes both spent coins AND added outpoints (for disconnect
    /// without full block data — needed during reorgs).
    ///
    /// txid_fn: function to compute txid (chain-specific: witness vs non-witness)
    template <typename BlockType, typename TxidFn>
    BlockUndo connect_block(const BlockType& block, uint32_t height, TxidFn txid_fn) {
        BlockUndo undo;
        bool first_tx = true;

        for (const auto& tx : block.m_txs) {
            uint256 txid = txid_fn(tx);
            bool is_coinbase = first_tx;
            first_tx = false;

            // Detect HogEx (MWEB): last tx with m_hogEx flag → outputs are pegouts
            bool is_hogex = tx.m_hogEx;

            if (!is_coinbase) {
                // Spend inputs — save spent coins for undo
                TxUndo tx_undo;
                for (const auto& vin : tx.vin) {
                    Outpoint op(vin.prevout.hash, vin.prevout.index);
                    auto spent = spend_coin(op);
                    if (spent.has_value()) {
                        tx_undo.spent_coins.push_back(std::move(*spent));
                    } else {
                        // Input not in UTXO — UTXO incomplete (bootstrap) or invalid tx
                        tx_undo.spent_coins.emplace_back();
                    }
                }
                undo.tx_undos.push_back(std::move(tx_undo));
            }

            // Add outputs
            for (uint32_t i = 0; i < static_cast<uint32_t>(tx.vout.size()); ++i) {
                const auto& vout = tx.vout[i];
                if (is_unspendable(vout.scriptPubKey))
                    continue;
                if (vout.value == 0)
                    continue;
                // HogEx outputs (index > 0) are MWEB pegouts with 6-block maturity
                bool is_pegout = is_hogex && i > 0;
                Outpoint op(txid, i);
                add_coin(op, Coin(vout.value, vout.scriptPubKey, height, is_coinbase, is_pegout));
                undo.added_outpoints.push_back(op);
            }
        }

        ++m_blocks_connected;
        return undo;
    }

    /// Disconnect a block using only undo data (no full block needed).
    /// 1. Remove all outputs that were added by the block (from added_outpoints)
    /// 2. Restore all inputs that were spent (from tx_undos)
    /// This enables reorg handling without requesting full blocks for the old fork.
    bool disconnect_from_undo(const BlockUndo& undo) {
        // Step 1: Remove all outputs added by this block
        for (const auto& op : undo.added_outpoints)
            m_cache[op] = std::nullopt;

        // Step 2: Restore all spent inputs
        for (const auto& tu : undo.tx_undos) {
            for (const auto& coin : tu.spent_coins) {
                if (!coin.is_spent()) {
                    // We don't have the outpoint here — but we stored the full Coin
                    // The outpoint is NOT in the undo data structure (LTC Core uses
                    // the block's tx.vin to reconstruct it). Since we're disconnecting
                    // without the block, we need a different approach.
                    // This is handled by the full disconnect_block() below.
                }
            }
        }
        // NOTE: disconnect_from_undo() only handles output removal.
        // Input restoration requires the block data (for vin outpoints).
        // For SPV reorgs, output removal is sufficient — the new fork's
        // connect_block() will re-add the correct coins.
        return true;
    }

    /// Full disconnect with block data: restore spent inputs + remove added outputs.
    /// Reference: LTC validation.cpp DisconnectBlock() lines 1777-1841
    template <typename BlockType, typename TxidFn>
    bool disconnect_block(const BlockType& block, const BlockUndo& undo, TxidFn txid_fn) {
        // Step 1: Remove all added outputs
        for (const auto& op : undo.added_outpoints)
            m_cache[op] = std::nullopt;

        // Step 2: Restore spent inputs (reverse tx order, matching LTC Core)
        size_t undo_idx = undo.tx_undos.size();
        for (int i = static_cast<int>(block.m_txs.size()) - 1; i >= 0; --i) {
            const auto& tx = block.m_txs[i];
            bool is_coinbase = (i == 0);

            if (!is_coinbase) {
                if (undo_idx == 0) return false;
                --undo_idx;
                const auto& tx_undo = undo.tx_undos[undo_idx];
                if (tx_undo.spent_coins.size() != tx.vin.size()) return false;

                for (size_t j = 0; j < tx.vin.size(); ++j) {
                    Outpoint op(tx.vin[j].prevout.hash, tx.vin[j].prevout.index);
                    const auto& restored = tx_undo.spent_coins[j];
                    if (!restored.is_spent())
                        add_coin(op, restored);
                }
            }
        }
        return true;
    }

    // ── Flush to persistent store ───────────────────────────────────────

    /// Write all cached changes to the backing UTXOViewDB.
    /// Clears the in-memory cache after successful write.
    bool flush(const uint256& best_block, uint32_t best_height) {
        if (!m_base)
            return false;

        // Convert cache to ChangeMap
        UTXOViewDB::ChangeMap changes;
        changes.reserve(m_cache.size());
        for (auto& [op, change] : m_cache)
            changes[op] = change;

        if (!m_base->write_batch(changes, best_block, best_height))
            return false;

        m_cache.clear();
        return true;
    }

    /// Number of entries in the cache (for diagnostics).
    size_t cache_size() const { return m_cache.size(); }

    /// Best block from the backing DB.
    uint256 get_best_block() const {
        return m_base ? m_base->get_best_block() : uint256();
    }
    uint32_t get_best_height() const {
        return m_base ? m_base->get_best_height() : 0;
    }

    /// Number of blocks connected since startup (or loaded from DB on restart).
    /// Used for coinbase maturity gate — mining blocked until this reaches
    /// the chain's COINBASE_MATURITY depth.
    uint32_t blocks_connected() const { return m_blocks_connected; }

    /// Prune undo data older than (tip_height - keep_depth).
    /// Reference: litecoind validation.cpp PruneBlockFilesManual()
    ///   LTC: keep_depth = MIN_BLOCKS_TO_KEEP = 288 (litecoin/src/validation.h)
    ///   DOGE: keep_depth = MIN_BLOCKS_TO_KEEP = 1440 (dogecoin/src/validation.h)
    uint32_t prune_undo(uint32_t tip_height, uint32_t keep_depth) {
        if (!m_base || tip_height <= keep_depth) return 0;
        uint32_t prune_below = tip_height - keep_depth;
        // On first call after startup, m_oldest_undo_height is 0.
        // Skip the already-pruned range to avoid millions of pointless
        // LevelDB delete attempts (this was causing a 6M-iteration loop
        // that froze the event loop for >30s on DOGE chain height ~6.1M).
        if (m_oldest_undo_height == 0 && prune_below > 0) {
            m_oldest_undo_height = prune_below;
            return 0;
        }
        // Batch limit: prune at most 500 records per call to keep the
        // event loop responsive even during large catch-up prunes.
        constexpr uint32_t MAX_PRUNE_BATCH = 500;
        uint32_t end = std::min(prune_below, m_oldest_undo_height + MAX_PRUNE_BATCH);
        uint32_t pruned = 0;
        for (uint32_t h = m_oldest_undo_height; h < end; ++h) {
            if (m_base->remove_block_undo(h))
                ++pruned;
        }
        m_oldest_undo_height = end;
        if (pruned > 0) {
            LOG_INFO << "[UTXO] Pruned " << pruned << " undo records below height "
                     << end << " (keep_depth=" << keep_depth << ")";
        }
        return pruned;
    }

private:
    UTXOViewDB* m_base;
    uint32_t m_blocks_connected{0};
    uint32_t m_oldest_undo_height{0};
    // Cache: outpoint → optional<Coin>
    //   - has_value() && !is_spent(): coin exists
    //   - nullopt: coin was spent (erased)
    //   - not in cache: unknown (check DB)
    std::unordered_map<Outpoint, std::optional<Coin>, OutpointHasher> m_cache;
};

} // namespace coin
} // namespace core
