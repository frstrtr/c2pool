// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

/// Phase C-MEMPOOL step 1: in-memory Dash mempool.
///
/// Adapted from src/impl/ltc/coin/mempool.hpp (~735 LOC) with these
/// Dash-specific simplifications:
///   - No segwit → no TX_WITH_WITNESS / TX_NO_WITNESS distinction; just
///     `pack(tx)` and `dash::coin::dash_txid()`.
///   - No weight calculation → just base_size = sizeof serialized tx.
///   - No wtxid index (BIP 152 v2 never reaches Dash; we already pin
///     CMPCTBLOCKS_VERSION=1 in Phase U).
///   - Special-tx (type 1-4 ProTx, type 5 CCbTx, type 6 quorum
///     commitment) are stored as opaque MutableTransaction blobs;
///     consumers (Phase C-PAY's state machine, future block-template
///     builder) decode their own way.
///
/// Step 1 SCOPE: storage layer + UTXO fee + LRU size-cap eviction +
/// confirm-eviction + double-spend conflict detection. All thread-safe
/// via single std::mutex.
///
/// Step 2 ADDS:
///   - Feerate-sorted index (m_feerate_index) maintained on add/remove
///   - get_sorted_txs_with_fees(max_bytes): highest-feerate-first
///     selection up to a byte cap, with stale-input guard. Phase
///     C-TEMPLATE prerequisite.
///   - recompute_unknown_fees(utxo): re-attempts fee computation for
///     entries marked fee_known=false (typically after a block
///     connect added their inputs to UTXO).
///
/// DEFERRED (later steps):
///   - BIP 35 mempool initial sync drain (step 3 — wire already in
///     p2p_node.hpp, no consumer yet)
///   - revalidate_inputs (evict txs whose inputs got spent without
///     us catching it via remove_for_block conflict path)
///   - Orphan-children removal after conflict eviction
///   - Lightweight summary API for the explorer/dashboard

#include "block.hpp"
#include "transaction.hpp"
#include "utxo_adapter.hpp"
#include "vendor/assetlock.hpp"   // DIP-0027 CAssetUnlockPayload (type-9 fee source)

#include <core/uint256.hpp>
#include <core/pack.hpp>
#include <core/hash.hpp>
#include <core/log.hpp>
#include <core/coin/utxo_view_cache.hpp>

#include <atomic>
#include <cstdint>
#include <ctime>
#include <map>
#include <set>
#include <mutex>
#include <optional>
#include <utility>
#include <vector>

namespace dash {
namespace coin {

struct MempoolEntry {
    MutableTransaction tx;
    uint256  txid;
    uint32_t base_size{0};
    uint64_t fee{0};            // satoshi (computed from UTXO when available)
    bool     fee_known{false};
    time_t   time_added{0};

    double feerate_satvb() const {
        return (fee_known && base_size > 0)
            ? static_cast<double>(fee) / base_size
            : 0.0;
    }
};

/// Deterministic block-template selection key. Sorts highest-feerate
/// first; ties broken by txid ascending. Byte-reproducible across
/// nodes/runs AND bit-for-bit conformant with dashcore BlockAssembler
/// ordering. dashcore CompareTxMemPoolEntryByAncestorFee compares two
/// entries by cross-multiplication of (fee, size) as doubles --
/// f1 = a.fee * b.size vs f2 = b.fee * a.size -- explicitly "avoid
/// division by rewriting (a/b > c/d) as (a*d > c*b)". A pre-divided
/// fee/base_size double rounds where the cross-multiply does not, so the
/// two representations can order a tie-pair differently. We therefore
/// carry (fee, base_size) and reproduce the exact double cross-multiply;
/// equal feerate is broken by GetHash()/txid ascending, as the oracle
/// does. (No ancestor packages in this simplified mempool, so
/// GetModFeeAndSize reduces to the entry's own (fee, base_size).)
struct FeeKey {
    uint64_t fee;        // satoshi
    uint32_t base_size;  // serialized bytes (>0 for every indexed entry)
    uint256  txid;
    bool operator<(const FeeKey& o) const {
        // dashcore CompareTxMemPoolEntryByAncestorFee, division-free form.
        const double f1 = static_cast<double>(fee)   * o.base_size;
        const double f2 = static_cast<double>(o.fee) * base_size;
        if (f1 != f2) return f1 > f2;   // higher feerate first
        return txid < o.txid;           // txid asc tiebreak (oracle-conformant)
    }
};

class Mempool {
public:
    static constexpr size_t DEFAULT_MAX_BYTES   = 300ULL * 1024 * 1024;
    static constexpr time_t DEFAULT_EXPIRY_SECS = 14 * 24 * 3600;

    explicit Mempool(size_t max_bytes  = DEFAULT_MAX_BYTES,
                     time_t expiry_sec = DEFAULT_EXPIRY_SECS)
        : m_max_bytes(max_bytes)
        , m_expiry_sec(expiry_sec)
    {}

    Mempool(const Mempool&) = delete;
    Mempool& operator=(const Mempool&) = delete;

    void set_utxo(::core::coin::UTXOViewCache* u) { m_utxo.store(u); }

    // ── Mutation ────────────────────────────────────────────────────

    /// Add a transaction. Returns false if already known. When `utxo`
    /// is passed (or set_utxo was called), attempts fee computation;
    /// falls back to fee_known=false on missing-input.
    bool add_tx(const MutableTransaction& tx)
    {
        return add_tx(tx, m_utxo.load());
    }

    bool add_tx(const MutableTransaction& tx,
                ::core::coin::UTXOViewCache* utxo)
    {
        uint256 txid = dash_txid(tx);

        std::lock_guard<std::mutex> lock(m_mutex);
        if (m_pool.count(txid)) return false;

        MempoolEntry entry;
        entry.tx         = tx;
        entry.txid       = txid;
        auto packed      = ::pack(tx);
        entry.base_size  = static_cast<uint32_t>(packed.size());
        entry.time_added = std::time(nullptr);

        compute_fee_locked(entry, utxo);

        // LRU eviction if over size cap.
        int evicted = 0;
        while (m_total_bytes + entry.base_size > m_max_bytes
               && !m_time_index.empty()) {
            evict_one_locked(m_time_index.begin()->second);
            ++evicted;
        }

        m_pool[txid] = std::move(entry);
        auto& stored = m_pool[txid];
        m_time_index.emplace(stored.time_added, txid);
        m_total_bytes += stored.base_size;

        // Spent-outputs index for double-spend conflict detection.
        for (const auto& vin : stored.tx.vin) {
            m_spent_outputs[std::make_pair(
                vin.prevout.hash, vin.prevout.index)] = txid;
        }

        // Feerate-sorted index (step 2) — only if fee was known.
        // Unknown-fee txs sit out of the sorted view until
        // recompute_unknown_fees() resolves them after a UTXO update.
        // Uses negative feerate as the multimap key so begin() = best.
        if (stored.fee_known) {
            m_feerate_index.insert(FeeKey{stored.fee, stored.base_size, txid});
        }

        // Periodic stats — every 100 entries + first 5 + every eviction.
        if (m_pool.size() % 100 == 0 || m_pool.size() <= 5 || evicted > 0) {
            LOG_INFO << "[MEMPOOL] add txid=" << txid.GetHex().substr(0, 16)
                     << " size=" << m_pool.size()
                     << " bytes=" << m_total_bytes << "/" << m_max_bytes
                     << " base=" << stored.base_size
                     << " fee=" << (stored.fee_known
                                    ? std::to_string(stored.fee) : "?")
                     << (evicted > 0 ? " evict=" + std::to_string(evicted) : "");
        }
        return true;
    }

    void remove_tx(const uint256& txid)
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        remove_tx_locked(txid);
    }

    /// Eviction on block confirm. Two phases:
    ///   1. Remove every confirmed tx by txid.
    ///   2. Remove mempool txs that spend the same outputs as confirmed
    ///      txs (double-spend conflicts).
    void remove_for_block(const dash::coin::BlockType& block)
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        int removed = 0, conflicts = 0;

        // Phase 1
        for (const auto& mtx : block.m_txs) {
            uint256 txid = dash_txid(mtx);
            if (m_pool.count(txid)) ++removed;
            remove_tx_locked(txid);
        }

        // Phase 2
        for (const auto& mtx : block.m_txs) {
            for (const auto& vin : mtx.vin) {
                auto key = std::make_pair(vin.prevout.hash,
                                          vin.prevout.index);
                auto it = m_spent_outputs.find(key);
                if (it == m_spent_outputs.end()) continue;
                auto conflict_txid = it->second;
                if (m_pool.count(conflict_txid)) {
                    LOG_INFO << "[MEMPOOL] removing conflict tx "
                             << conflict_txid.GetHex().substr(0, 16)
                             << " (spends same input as confirmed tx "
                             << dash_txid(mtx).GetHex().substr(0, 16) << ")";
                    ++conflicts;
                }
                remove_tx_locked(conflict_txid);
            }
        }

        if (removed > 0 || conflicts > 0) {
            LOG_INFO << "[MEMPOOL] block cleanup removed=" << removed
                     << " conflicts=" << conflicts
                     << " remaining=" << m_pool.size();
        }
    }

    void evict_expired()
    {
        time_t cutoff = std::time(nullptr) - m_expiry_sec;
        std::lock_guard<std::mutex> lock(m_mutex);
        int evicted = 0;
        while (!m_time_index.empty()
               && m_time_index.begin()->first < cutoff) {
            evict_one_locked(m_time_index.begin()->second);
            ++evicted;
        }
        if (evicted > 0) {
            LOG_INFO << "[MEMPOOL] expiry sweep evicted " << evicted
                     << " entries (older than " << (m_expiry_sec / 3600)
                     << "h), remaining=" << m_pool.size();
        }
    }

    void clear()
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_pool.clear();
        m_time_index.clear();
        m_spent_outputs.clear();
        m_feerate_index.clear();
        m_total_bytes = 0;
    }

    /// Re-attempt fee computation for entries marked fee_known=false.
    /// Call after a block-connect: the block's outputs are now in
    /// UTXO and may resolve previously-unknown inputs. Returns the
    /// number of newly-resolved entries.
    int recompute_unknown_fees(::core::coin::UTXOViewCache* utxo)
    {
        if (!utxo) return 0;
        std::lock_guard<std::mutex> lock(m_mutex);
        int resolved = 0, still_unknown = 0;
        uint64_t resolved_fees = 0;
        for (auto& [txid, entry] : m_pool) {
            if (entry.fee_known) continue;
            if (compute_fee_locked(entry, utxo)) {
                m_feerate_index.insert(FeeKey{entry.fee, entry.base_size, txid});
                resolved_fees += entry.fee;
                ++resolved;
            } else {
                ++still_unknown;
            }
        }
        if (resolved > 0 || still_unknown > 0) {
            LOG_INFO << "[MEMPOOL] fee revalidation: resolved=" << resolved
                     << " still_unknown=" << still_unknown
                     << " resolved_fees=" << resolved_fees << " sat"
                     << " pool_size=" << m_pool.size();
        }
        return resolved;
    }

    // ── Queries ────────────────────────────────────────────────────

    bool contains(const uint256& txid) const
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_pool.count(txid) > 0;
    }

    size_t size() const
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_pool.size();
    }

    size_t byte_size() const
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_total_bytes;
    }

    uint64_t total_known_fees() const
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        uint64_t sum = 0;
        for (const auto& [_, e] : m_pool) {
            if (e.fee_known) sum += e.fee;
        }
        return sum;
    }

    std::optional<MempoolEntry> get_entry(const uint256& txid) const
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        auto it = m_pool.find(txid);
        if (it == m_pool.end()) return std::nullopt;
        return it->second;
    }

    std::vector<uint256> all_txids() const
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        std::vector<uint256> out;
        out.reserve(m_pool.size());
        for (auto& [txid, _] : m_pool) out.push_back(txid);
        return out;
    }

    /// Snapshot of all transactions keyed by txid. Used (eventually)
    /// by BIP 152 compact-block reconstruction + by block-template
    /// builder in Phase C-TEMPLATE.
    std::map<uint256, MutableTransaction> all_txs_map() const
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        std::map<uint256, MutableTransaction> out;
        for (const auto& [txid, e] : m_pool) out[txid] = e.tx;
        return out;
    }

    /// Phase C-TEMPLATE prerequisite — fee-aware tx selection.
    /// Returns transactions sorted by feerate (highest first) up to
    /// `max_bytes` of base-size budget. Transactions with unknown
    /// fees are EXCLUDED — they'd poison the coinbasevalue if we
    /// included them at fee=0 vs dashd's GBT (which always knows
    /// fees because it sees the full mempool with full UTXO).
    ///
    /// Stale-input guard: re-checks each candidate's inputs against
    /// the live UTXO + parent-mempool chain before including. Catches
    /// the brief window between tip-change and full_block arrival
    /// where remove_for_block hasn't yet evicted now-double-spent
    /// txs.
    ///
    /// Returns (selected, total_fees_sat).
    struct SelectedTx {
        MutableTransaction tx;
        uint64_t           fee{0};
        uint32_t           base_size{0};
    };

    std::pair<std::vector<SelectedTx>, uint64_t>
    get_sorted_txs_with_fees(uint32_t max_bytes) const
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        std::vector<SelectedTx> result;
        uint64_t total_fees = 0;
        uint32_t total_bytes = 0;
        auto* utxo = m_utxo.load();

        for (const auto& fk : m_feerate_index) {
            const uint256& txid = fk.txid;
            auto pit = m_pool.find(txid);
            if (pit == m_pool.end()) continue;
            const auto& entry = pit->second;
            if (!entry.fee_known) continue;
            if (total_bytes + entry.base_size > max_bytes) continue;

            // Stale-input guard.
            if (utxo) {
                bool ok = true;
                for (const auto& vin : entry.tx.vin) {
                    ::core::coin::Outpoint op(
                        vin.prevout.hash, vin.prevout.index);
                    ::core::coin::Coin coin;
                    if (utxo->get_coin(op, coin)) continue;
                    // Parent-mempool chain (CPFP).
                    auto parent = m_pool.find(vin.prevout.hash);
                    if (parent != m_pool.end()
                        && vin.prevout.index < parent->second.tx.vout.size()) {
                        continue;
                    }
                    ok = false;
                    break;
                }
                if (!ok) continue;
            }

            total_bytes += entry.base_size;
            total_fees  += entry.fee;
            result.push_back({entry.tx, entry.fee, entry.base_size});
        }
        return {std::move(result), total_fees};
    }

private:
    mutable std::mutex                                 m_mutex;
    std::map<uint256, MempoolEntry>                    m_pool;
    std::multimap<time_t, uint256>                     m_time_index;
    std::map<std::pair<uint256, uint32_t>, uint256>    m_spent_outputs;
    // Step 2: feerate-sorted index. greater<double> means begin() =
    // highest feerate, so iteration is best-first.
    std::set<FeeKey>                                   m_feerate_index;
    size_t                                             m_total_bytes{0};
    size_t                                             m_max_bytes;
    time_t                                             m_expiry_sec;
    std::atomic<::core::coin::UTXOViewCache*>          m_utxo{nullptr};

    void evict_one_locked(const uint256& txid)
    {
        remove_tx_locked(txid);
    }

    void remove_tx_locked(const uint256& txid)
    {
        auto it = m_pool.find(txid);
        if (it == m_pool.end()) return;

        // Drop from time index.
        auto trng = m_time_index.equal_range(it->second.time_added);
        for (auto rit = trng.first; rit != trng.second; ++rit) {
            if (rit->second == txid) {
                m_time_index.erase(rit);
                break;
            }
        }

        // Drop from feerate index (only present if fee was known).
        if (it->second.fee_known) {
            m_feerate_index.erase(FeeKey{it->second.fee, it->second.base_size, txid});
        }

        // Drop from spent-outputs index.
        for (const auto& vin : it->second.tx.vin) {
            auto key = std::make_pair(vin.prevout.hash, vin.prevout.index);
            auto sit = m_spent_outputs.find(key);
            if (sit != m_spent_outputs.end() && sit->second == txid) {
                m_spent_outputs.erase(sit);
            }
        }

        m_total_bytes -= it->second.base_size;
        m_pool.erase(it);
    }

    /// Compute fee = sum(input_values) - sum(output_values).
    /// Inputs come from UTXO set (confirmed); falls back to parent
    /// mempool tx outputs (CPFP / chain-of-unconfirmed). Sets
    /// entry.fee_known on success.
    bool compute_fee_locked(MempoolEntry& entry,
                            ::core::coin::UTXOViewCache* utxo)
    {
        // DIP-0027 asset-UNLOCK special case (type 9, E2b/#738). An
        // asset-unlock tx mints UTXO from the credit pool and carries NO
        // regular inputs, so the generic in-minus-out path below yields
        // in_sum(0) < out_sum -> permanently fee_known=false, and the
        // conservative selection guard would exclude it forever. Its miner
        // fee is EXPLICIT in the payload (CAssetUnlockPayload.fee — the
        // amount deducted from the unlock total for the miner's coinbase;
        // vendor/assetlock.hpp), exactly what dashd's GBT reports for it.
        // Pricing from the payload needs no UTXO view, so this branch sits
        // ahead of the null-utxo bail-out. TARGETED: only an input-free
        // type-9 body with a well-formed payload qualifies; anything else
        // (including a malformed type-9) falls through to / stays on the
        // conservative unknown-fee path. The general unknown-fee exclusion
        // for every other tx class is untouched.
        if (entry.tx.type == vendor::CAssetUnlockPayload::SPECIALTX_TYPE
            && entry.tx.vin.empty()) {
            vendor::CAssetUnlockPayload payload;
            if (vendor::parse_assetunlock_payload(entry.tx.extra_payload,
                                                  payload)) {
                entry.fee = payload.fee;
                entry.fee_known = true;
                return true;
            }
            entry.fee_known = false;
            entry.fee = 0;
            return false;
        }

        if (!utxo) {
            entry.fee_known = false;
            return false;
        }
        uint64_t in_sum = 0, out_sum = 0;
        for (const auto& vin : entry.tx.vin) {
            ::core::coin::Outpoint op(vin.prevout.hash, vin.prevout.index);
            ::core::coin::Coin coin;
            if (utxo->get_coin(op, coin)) {
                in_sum += static_cast<uint64_t>(coin.value);
                continue;
            }
            // Try parent mempool tx (CPFP).
            auto pit = m_pool.find(vin.prevout.hash);
            if (pit != m_pool.end()
                && vin.prevout.index < pit->second.tx.vout.size()) {
                in_sum += static_cast<uint64_t>(
                    pit->second.tx.vout[vin.prevout.index].value);
                continue;
            }
            entry.fee_known = false;
            entry.fee = 0;
            return false;
        }
        for (const auto& vout : entry.tx.vout) {
            out_sum += static_cast<uint64_t>(vout.value);
        }
        if (in_sum < out_sum) {
            // Negative fee — invalid tx; mark unknown so we don't
            // poison block templates with garbage values.
            entry.fee_known = false;
            entry.fee = 0;
            return false;
        }
        entry.fee = in_sum - out_sum;
        entry.fee_known = true;
        return true;
    }
};

} // namespace coin
} // namespace dash