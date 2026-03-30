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
    explicit UTXOViewCache(UTXOViewDB* base) : m_base(base) {}

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
    ///
    /// coinbase_txid_fn: function to compute txid from a transaction
    /// (needed because txid computation is chain-specific: witness vs non-witness)
    template <typename BlockType, typename TxidFn>
    BlockUndo connect_block(const BlockType& block, uint32_t height, TxidFn txid_fn) {
        BlockUndo undo;
        bool first_tx = true;

        for (const auto& tx : block.m_txs) {
            uint256 txid = txid_fn(tx);
            bool is_coinbase = first_tx;
            first_tx = false;

            if (!is_coinbase) {
                // Spend inputs — save spent coins for undo
                TxUndo tx_undo;
                for (const auto& vin : tx.vin) {
                    Outpoint op(vin.prevout.hash, vin.prevout.index);
                    auto spent = spend_coin(op);
                    if (spent.has_value()) {
                        tx_undo.spent_coins.push_back(std::move(*spent));
                    } else {
                        // Input not in UTXO — either UTXO is incomplete (bootstrap)
                        // or this is a truly invalid tx. Store empty coin for undo.
                        tx_undo.spent_coins.emplace_back();
                    }
                }
                undo.tx_undos.push_back(std::move(tx_undo));
            }

            // Add outputs
            for (uint32_t i = 0; i < static_cast<uint32_t>(tx.vout.size()); ++i) {
                const auto& vout = tx.vout[i];
                // Skip unspendable outputs (OP_RETURN)
                if (!vout.scriptPubKey.m_data.empty() && vout.scriptPubKey.m_data[0] == 0x6a)
                    continue;
                if (vout.value == 0)
                    continue;
                Outpoint op(txid, i);
                add_coin(op, Coin(vout.value, vout.scriptPubKey, height, is_coinbase));
            }
        }

        return undo;
    }

    /// Disconnect a block: restore spent inputs, remove added outputs.
    template <typename BlockType, typename TxidFn>
    bool disconnect_block(const BlockType& block, uint32_t height,
                          const BlockUndo& undo, TxidFn txid_fn) {
        // Process transactions in reverse order (matching Litecoin Core)
        size_t undo_idx = undo.tx_undos.size();
        bool first_tx_from_end = false;

        for (int i = static_cast<int>(block.m_txs.size()) - 1; i >= 0; --i) {
            const auto& tx = block.m_txs[i];
            uint256 txid = txid_fn(tx);
            bool is_coinbase = (i == 0);

            // Remove outputs added by this block
            for (uint32_t j = 0; j < static_cast<uint32_t>(tx.vout.size()); ++j) {
                Outpoint op(txid, j);
                m_cache[op] = std::nullopt;  // mark as spent/removed
            }

            // Restore inputs from undo data
            if (!is_coinbase) {
                if (undo_idx == 0) {
                    LOG_ERROR << "[UTXO] disconnect_block: undo data underflow at tx " << i;
                    return false;
                }
                --undo_idx;
                const auto& tx_undo = undo.tx_undos[undo_idx];

                if (tx_undo.spent_coins.size() != tx.vin.size()) {
                    LOG_ERROR << "[UTXO] disconnect_block: undo coin count mismatch"
                              << " expected=" << tx.vin.size()
                              << " got=" << tx_undo.spent_coins.size();
                    return false;
                }

                for (size_t j = 0; j < tx.vin.size(); ++j) {
                    Outpoint op(tx.vin[j].prevout.hash, tx.vin[j].prevout.index);
                    const auto& restored = tx_undo.spent_coins[j];
                    if (!restored.is_spent()) {
                        add_coin(op, restored);
                    }
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

private:
    UTXOViewDB* m_base;
    // Cache: outpoint → optional<Coin>
    //   - has_value() && !is_spent(): coin exists
    //   - nullopt: coin was spent (erased)
    //   - not in cache: unknown (check DB)
    std::unordered_map<Outpoint, std::optional<Coin>, OutpointHasher> m_cache;
};

} // namespace coin
} // namespace core
