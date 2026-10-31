#pragma once

/// UTXOViewCache: In-memory write-back UTXO cache.
///
/// Backed by UTXOViewDB (LevelDB). Changes are buffered in memory and
/// flushed atomically per block via flush().
///
/// Thread safety: internally synchronized via std::shared_mutex.
///   - reads (get_coin/have_coin/get_value_in/compute_fee/queries) take a
///     shared_lock
///   - mutators (add_coin/spend_coin/connect_block/disconnect_*/flush/prune_undo)
///     take a unique_lock
///
/// Every public method is safe to call from any thread. Internally, public
/// methods delegate to private *_locked helpers so write paths can call read
/// helpers without re-locking. This is a temporary safety net while the
/// codebase migrates to a per-chain boost::asio strand owning the UTXO domain
/// (see frstrtr/the/docs/c2pool-utxo-thread-race-task.md option B). Once the
/// strand owns the data, this mutex becomes redundant and can be removed.
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
        std::shared_lock<std::shared_mutex> lock(m_mu);
        return get_coin_locked(op, coin);
    }

    /// Check if a coin exists (not spent).
    bool have_coin(const Outpoint& op) {
        std::shared_lock<std::shared_mutex> lock(m_mu);
        auto it = m_cache.find(op);
        if (it != m_cache.end())
            return it->second.has_value();
        if (m_base)
            return m_base->have_coin(op);
        return false;
    }

    /// Get the value of a specific output. Returns -1 if not found.
    int64_t get_output_value(const Outpoint& op) {
        std::shared_lock<std::shared_mutex> lock(m_mu);
        Coin coin;
        if (get_coin_locked(op, coin))
            return coin.value;
        return -1;
    }

    // ── Write operations ────────────────────────────────────────────────

    /// Add a coin to the cache. Overwrites any existing entry.
    void add_coin(const Outpoint& op, Coin coin) {
        std::unique_lock<std::shared_mutex> lock(m_mu);
        m_cache[op] = std::move(coin);
    }

    /// Mark a coin as spent. Returns the coin that was spent (for undo data).
    /// Returns std::nullopt if coin was not found.
    std::optional<Coin> spend_coin(const Outpoint& op) {
        std::unique_lock<std::shared_mutex> lock(m_mu);
        Coin coin;
        if (!get_coin_locked(op, coin))
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
        std::shared_lock<std::shared_mutex> lock(m_mu);
        return get_value_in_locked(tx);
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
        std::shared_lock<std::shared_mutex> lock(m_mu);
        auto [value_in, found] = get_value_in_locked(tx);
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
    /// Undo includes the spent coins with their outpoints AND the added
    /// outpoints (for disconnect without full block data — needed during
    /// reorgs).
    ///
    /// txid_fn: function to compute txid (chain-specific: witness vs non-witness)
    /// block_hash: stored in the record so a disconnect can check that the
    ///   record belongs to the block it undoes (null = unbound)
    template <typename BlockType, typename TxidFn>
    BlockUndo connect_block(const BlockType& block, uint32_t height, TxidFn txid_fn,
                            const uint256& block_hash = uint256()) {
        std::unique_lock<std::shared_mutex> lock(m_mu);
        BlockUndo undo;
        undo.block_hash = block_hash;
        bool first_tx = true;

        for (const auto& tx : block.m_txs) {
            uint256 txid = txid_fn(tx);
            bool is_coinbase = first_tx;
            first_tx = false;

            // Detect HogEx (MWEB): last tx with m_hogEx flag → outputs are pegouts.
            // BTC's MutableTransaction has no m_hogEx (no MWEB) — gate by requires.
            bool is_hogex = false;
            if constexpr (requires { tx.m_hogEx; }) {
                is_hogex = tx.m_hogEx;
            }

            if (!is_coinbase) {
                // Spend inputs — save spent coins and their outpoints for undo,
                // index-aligned with tx.vin
                TxUndo tx_undo;
                for (const auto& vin : tx.vin) {
                    Outpoint op(vin.prevout.hash, vin.prevout.index);
                    Coin spent;
                    if (get_coin_locked(op, spent)) {
                        m_cache[op] = std::nullopt;  // mark as spent
                        tx_undo.spent_coins.push_back(std::move(spent));
                    } else {
                        // Input not in UTXO — UTXO incomplete (bootstrap) or invalid tx
                        tx_undo.spent_coins.emplace_back();
                    }
                    tx_undo.spent_outpoints.push_back(op);
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
                m_cache[op] = Coin(vout.value, vout.scriptPubKey, height, is_coinbase, is_pegout);
                undo.added_outpoints.push_back(op);
            }
        }

        ++m_blocks_connected;
        return undo;
    }

    /// The first input a strict connect could not find.
    struct StrictRefusal {
        Outpoint missing;      // the input's prevout
        uint256  txid;         // the transaction spending it
        uint32_t tx_index{0};  // its position in the block
        bool     spent_in_block{false};  // an earlier tx of the same block spent it (no valid
                                         // block does: a mutated or forged body)
    };

    /// connect_block with the mode explicit. strict = false is the call above
    /// (an input the view does not hold is recorded as unknown: a partial
    /// view). strict = true is for a set built from genesis: every input must
    /// be a coin the view holds, or an output of an earlier transaction of the
    /// same block, and each is spent once (Dogecoin Core CheckTxInputs,
    /// bad-txns-inputs-missingorspent). Otherwise the block is refused:
    /// nullopt, nothing touched, `why` names the input.
    /// A strict connect keeps zero-value outputs, as Core's chainstate does
    /// (only an IsUnspendable output is left out: coins.h ClearUnspendable),
    /// and counts the set's coins for the sync state.
    template <typename BlockType, typename TxidFn>
    std::optional<BlockUndo> connect_block(const BlockType& block, uint32_t height, TxidFn txid_fn,
                                           const uint256& block_hash, bool strict,
                                           StrictRefusal* why = nullptr) {
        if (!strict)
            return connect_block(block, height, txid_fn, block_hash);
        std::unique_lock<std::shared_mutex> lock(m_mu);
        // The block's changes, applied to the view only once every input resolved.
        std::unordered_map<Outpoint, std::optional<Coin>, OutpointHasher> overlay;
        bool spent_in_block = false;
        auto lookup = [&](const Outpoint& op, Coin& coin) {
            auto it = overlay.find(op);
            if (it != overlay.end()) {
                if (!it->second.has_value()) {
                    spent_in_block = true;  // spent earlier in this block
                    return false;
                }
                coin = *it->second;
                return true;
            }
            return get_coin_locked(op, coin);
        };
        BlockUndo undo;
        undo.block_hash = block_hash;
        int64_t delta = 0;
        for (size_t t = 0; t < block.m_txs.size(); ++t) {
            const auto& tx = block.m_txs[t];
            const uint256 txid = txid_fn(tx);
            const bool is_coinbase = t == 0;
            bool is_hogex = false;
            if constexpr (requires { tx.m_hogEx; }) {
                is_hogex = tx.m_hogEx;
            }
            if (!is_coinbase) {
                TxUndo tx_undo;
                for (const auto& vin : tx.vin) {
                    Outpoint op(vin.prevout.hash, vin.prevout.index);
                    Coin spent;
                    if (!lookup(op, spent)) {
                        if (why) {
                            why->missing = op;
                            why->txid = txid;
                            why->tx_index = static_cast<uint32_t>(t);
                            why->spent_in_block = spent_in_block;
                        }
                        return std::nullopt;
                    }
                    overlay[op] = std::nullopt;
                    tx_undo.spent_coins.push_back(std::move(spent));
                    tx_undo.spent_outpoints.push_back(op);
                    --delta;
                }
                undo.tx_undos.push_back(std::move(tx_undo));
            }
            for (uint32_t i = 0; i < static_cast<uint32_t>(tx.vout.size()); ++i) {
                const auto& vout = tx.vout[i];
                if (is_unspendable(vout.scriptPubKey))
                    continue;
                const bool is_pegout = is_hogex && i > 0;
                Outpoint op(txid, i);
                overlay[op] = Coin(vout.value, vout.scriptPubKey, height, is_coinbase, is_pegout);
                undo.added_outpoints.push_back(op);
                ++delta;
            }
        }
        for (auto& [op, change] : overlay)
            m_cache[op] = std::move(change);
        m_coin_delta += delta;
        ++m_blocks_connected;
        return undo;
    }

    /// Disconnect a block using only its undo record (no full block needed):
    /// put back every coin the block spent, then remove every output it added.
    /// Reference: LTC validation.cpp DisconnectBlock() lines 1777-1841,
    ///            ApplyTxInUndo() lines 1747-1773
    ///
    /// A legacy record (no outpoints, BlockUndo::restorable() false) cannot put
    /// the spent coins back: only the block's outputs are removed (a rolled-back
    /// coin must never price) and false is returned; the caller decides.
    bool disconnect_from_undo(const BlockUndo& undo) {
        std::unique_lock<std::shared_mutex> lock(m_mu);
        if (!undo.restorable()) {
            for (const auto& op : undo.added_outpoints)
                m_cache[op] = std::nullopt;
            LOG_ERROR << "[UTXO] legacy undo record (pre-#2059): " << undo.unrestorable_coins()
                      << " spent coin(s) cannot be restored; only the block's outputs were removed";
            return false;
        }
        disconnect_locked(undo);
        return true;
    }

    /// Full disconnect with block data, in Core's checked form: the record must
    /// match the block — one TxUndo per non-coinbase tx (Core L1787-1790), one
    /// coin per input (L1814-1817), each outpoint the input's prevout — before
    /// anything is touched; false otherwise. A legacy record takes its
    /// outpoints from the block. Then the same passes as disconnect_from_undo.
    /// Reference: LTC validation.cpp DisconnectBlock() lines 1777-1841
    template <typename BlockType, typename TxidFn>
    bool disconnect_block(const BlockType& block, const BlockUndo& undo, TxidFn /*txid_fn*/) {
        if (block.m_txs.empty() || undo.tx_undos.size() + 1 != block.m_txs.size())
            return false;
        bool legacy = false;
        for (size_t i = 1; i < block.m_txs.size(); ++i) {
            const auto& tx = block.m_txs[i];
            const auto& tu = undo.tx_undos[i - 1];
            if (tu.spent_coins.size() != tx.vin.size())
                return false;
            if (!tu.has_outpoints()) {
                legacy = true;
                continue;
            }
            for (size_t j = 0; j < tx.vin.size(); ++j) {
                if (tu.spent_outpoints[j] != Outpoint(tx.vin[j].prevout.hash, tx.vin[j].prevout.index))
                    return false;
            }
        }
        std::unique_lock<std::shared_mutex> lock(m_mu);
        if (!legacy) {
            disconnect_locked(undo);
            return true;
        }
        BlockUndo completed = undo;
        for (size_t i = 1; i < block.m_txs.size(); ++i) {
            auto& tu = completed.tx_undos[i - 1];
            if (tu.has_outpoints())
                continue;
            tu.spent_outpoints.clear();
            for (const auto& vin : block.m_txs[i].vin)
                tu.spent_outpoints.emplace_back(vin.prevout.hash, vin.prevout.index);
        }
        disconnect_locked(completed);
        return true;
    }

    // ── Flush to persistent store ───────────────────────────────────────

    /// Write all cached changes to the backing UTXOViewDB.
    /// Clears the in-memory cache after successful write.
    bool flush(const uint256& best_block, uint32_t best_height) {
        std::unique_lock<std::shared_mutex> lock(m_mu);
        if (!m_base)
            return false;

        // Convert cache to ChangeMap
        UTXOViewDB::ChangeMap changes;
        changes.reserve(m_cache.size());
        for (auto& [op, change] : m_cache)
            changes[op] = change;

        if (!m_base->write_batch(changes, best_block, best_height, m_coin_delta))
            return false;

        m_cache.clear();
        m_coin_delta = 0;
        return true;
    }

    /// Drop the changes not flushed yet (after a flush that failed): the
    /// view is the backing DB's again, at its best block.
    void discard_pending() {
        std::unique_lock<std::shared_mutex> lock(m_mu);
        m_cache.clear();
        m_coin_delta = 0;
    }

    // ── Sync state ('S', UTXOViewDB) ────────────────────────────────────

    /// The backing DB's sync state ({anchor unknown} without a DB or record).
    SyncState sync_state() const {
        std::shared_lock<std::shared_mutex> lock(m_mu);
        return m_base ? m_base->get_sync_state() : SyncState{};
    }

    /// Write the sync state (anchor, strict, synced); best_height and coins
    /// follow every flush from then on.
    bool set_sync_state(const SyncState& s) {
        std::unique_lock<std::shared_mutex> lock(m_mu);
        return m_base && m_base->put_sync_state(s);
    }

    /// First height whose coins the set holds (SyncState::ANCHOR_UNKNOWN: a
    /// legacy accrual view that never recorded one).
    uint32_t anchor_height() const { return sync_state().anchor_height; }

    /// The set holds every coin of the best chain up to its tip: it was
    /// built from genesis and its best block IS the tip (`chain_hash` at
    /// `chain_height`), not only at the tip's height (a sibling of the tip
    /// is not the tip's set).
    bool complete(uint32_t chain_height, const uint256& chain_hash) const {
        std::shared_lock<std::shared_mutex> lock(m_mu);
        if (!m_base || chain_hash.IsNull())
            return false;
        return m_base->get_sync_state().anchor_height == 0 && m_base->get_best_height() == chain_height
            && m_base->get_best_block() == chain_hash;
    }

    /// Re-anchor the view: drop all in-memory pending changes AND wipe the
    /// backing DB, resetting the accrual anchor to zero so the next
    /// connect_block() starts a fresh partial view from the current tip. Used
    /// by the full_block accrual handler on a forward tip-gap (e.g. after a
    /// restart) — see impl/dgb/coin/utxo_accrual.hpp and UTXOViewDB::reset().
    ///
    /// Fail-closed: if the backing wipe fails the cache is left UNTOUCHED and
    /// false is returned; the caller must then NOT connect the current block.
    /// With no backing DB (an in-memory-only view) there is nothing on disk to
    /// wipe — the in-memory cache and counters are still reset and true is
    /// returned.
    bool reanchor() {
        std::unique_lock<std::shared_mutex> lock(m_mu);
        if (m_base && !m_base->reset())
            return false;  // DB wipe failed -> fail-closed, cache held.
        m_cache.clear();
        m_blocks_connected = 0;
        m_oldest_undo_height = 0;
        m_coin_delta = 0;
        return true;
    }

    /// Number of entries in the cache (for diagnostics).
    size_t cache_size() const {
        std::shared_lock<std::shared_mutex> lock(m_mu);
        return m_cache.size();
    }

    /// Best block from the backing DB.
    uint256 get_best_block() const {
        std::shared_lock<std::shared_mutex> lock(m_mu);
        return m_base ? m_base->get_best_block() : uint256();
    }
    uint32_t get_best_height() const {
        std::shared_lock<std::shared_mutex> lock(m_mu);
        return m_base ? m_base->get_best_height() : 0;
    }

    /// Number of blocks connected since startup (or loaded from DB on restart).
    /// The LTC and accrual DOGE mining gates read it (coinbase maturity
    /// depth); a set with a sync state is gated by complete() instead.
    uint32_t blocks_connected() const {
        std::shared_lock<std::shared_mutex> lock(m_mu);
        return m_blocks_connected;
    }

    /// Prune undo data older than (tip_height - keep_depth).
    /// Reference: litecoind validation.cpp PruneBlockFilesManual()
    ///   LTC: keep_depth = MIN_BLOCKS_TO_KEEP = 288 (litecoin/src/validation.h)
    ///   DOGE: keep_depth = MIN_BLOCKS_TO_KEEP = 1440 (dogecoin/src/validation.h)
    uint32_t prune_undo(uint32_t tip_height, uint32_t keep_depth) {
        std::unique_lock<std::shared_mutex> lock(m_mu);
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
    // Internal helpers — caller must hold m_mu (shared for reads, unique for writes).
    // Lets writers (which hold a unique_lock) reuse read logic without re-acquiring.

    bool get_coin_locked(const Outpoint& op, Coin& coin) const {
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

    // The disconnect proper; the caller holds m_mu (unique) and every spent
    // coin that is not unknown has its outpoint (restorable() or completed).
    //
    // Core interleaves per tx (txs in reverse: remove the tx's outputs, then
    // restore its inputs in reverse). Two passes reach the same final state:
    // a pre-block coin the block spent is restored once, and an output the
    // block created ends absent even when a later tx of the same block spent
    // it (restored in pass 1, removed in pass 2; remove-then-restore would
    // resurrect it). As in Core, restoring over an existing coin and removing
    // an output that is not there make the disconnect unclean: an ERROR (it
    // means the set and the record disagree), but the disconnect completes.
    // Core's DisconnectTip refuses an unclean result, discarding its scratch
    // view; this cache has no scratch view, and Core's own replay rollback
    // (ReplayBlocks, validation.cpp:4568-4576) keeps going on an unclean
    // result because writing and deleting a coin are idempotent: the result is
    // still the set with the block's effects undone. A coin recorded as
    // unknown (not in the view at connect, e.g. a partial view after a jump
    // start) has nothing to restore.
    void disconnect_locked(const BlockUndo& undo) {
        size_t unknown = 0, overwrite = 0, missing = 0;
        // Pass 1 — restore spent inputs: txs in reverse, inputs in reverse
        // (Core DisconnectBlock L1792, L1818-1823; ApplyTxInUndo L1751).
        for (auto tu = undo.tx_undos.rbegin(); tu != undo.tx_undos.rend(); ++tu) {
            for (size_t j = tu->spent_coins.size(); j-- > 0;) {
                const Coin& c = tu->spent_coins[j];
                if (c.is_spent()) {
                    ++unknown;
                    continue;
                }
                const Outpoint& op = tu->spent_outpoints[j];
                Coin cur;
                if (get_coin_locked(op, cur))
                    ++overwrite;  // Core: overwriting transaction output
                else
                    ++m_coin_delta;
                m_cache[op] = c;  // value, script, height, coinbase, pegout
            }
        }
        // Pass 2 — remove the outputs the block added (Core L1797-1808).
        for (const auto& op : undo.added_outpoints) {
            Coin cur;
            if (!get_coin_locked(op, cur))
                ++missing;        // Core: transaction output mismatch
            else
                --m_coin_delta;
            m_cache[op] = std::nullopt;
        }
        if (overwrite || missing) {
            LOG_ERROR << "[UTXO] unclean disconnect: " << overwrite
                        << " restored coin(s) overwrote an existing coin, " << missing
                        << " added output(s) were already gone";
        }
        if (unknown) {
            LOG_DEBUG_COIND << "[UTXO] disconnect: " << unknown
                            << " spent coin(s) were not in the view at connect (nothing to restore)";
        }
    }

    template <typename TxType>
    std::pair<int64_t, bool> get_value_in_locked(const TxType& tx) const {
        int64_t total = 0;
        for (const auto& vin : tx.vin) {
            Outpoint op(vin.prevout.hash, vin.prevout.index);
            Coin coin;
            if (!get_coin_locked(op, coin))
                return {total, false};
            total += coin.value;
        }
        return {total, true};
    }

    mutable std::shared_mutex m_mu;
    UTXOViewDB* m_base;
    uint32_t m_blocks_connected{0};
    uint32_t m_oldest_undo_height{0};
    int64_t  m_coin_delta{0};  // coins added minus removed since the last flush (sync state)
    // Cache: outpoint → optional<Coin>
    //   - has_value() && !is_spent(): coin exists
    //   - nullopt: coin was spent (erased)
    //   - not in cache: unknown (check DB)
    std::unordered_map<Outpoint, std::optional<Coin>, OutpointHasher> m_cache;
};

} // namespace coin
} // namespace core
