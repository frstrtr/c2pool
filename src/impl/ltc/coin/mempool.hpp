// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

/// LTC Mempool — Phase 2 + UTXO fee computation
///
/// In-memory transaction pool receiving transactions from P2P peers.
/// When a UTXOViewCache is available, computes per-transaction fees
/// (sum_inputs - sum_outputs) and maintains a feerate-sorted index
/// for optimal block template building.
///
/// Thread-safe via internal mutex.
///
/// Admission (Mempool::admit) keeps out every tx an embedded LTC template
/// can never carry. Embedded c2pool emits an empty-body mw::Block and a
/// one-in/one-out HogEx, so its blocks hold no pegin output, no pegout and no
/// kernel, and no block tx may carry an mw::Transaction (litecoind
/// mweb_node.cpp CheckBlock / ContextualCheckBlock / ValidateMWEBBlock):
///   - a tx with an MWEB part (peg-in, peg-out, MWEB-to-MWEB or mixed);
///   - a pegin output without its kernel (mweb_policy.cpp kernel-mismatch);
///   - empty vin or vout, unless MWEB-only (consensus/tx_check.cpp);
///   - a HogEx (valid only in a block; validation.cpp PreChecks).
/// Children of a refused tx need no rule: their input is in neither the UTXO
/// set nor the pool, so their fee stays unknown and they are never selected.
///
/// Inputs (Dogecoin/Litecoin Core AcceptToMemoryPool):
///   - an input the view holds that is a premature coinbase (or pegout)
///     spend, a value out of money range, or outputs above inputs: refused
///     (Reject::inputs_invalid, Core CheckTxInputs);
///   - with a set built from genesis (anchor 0, UTXOViewCache::sync_state),
///     an input in neither the set nor the pool makes the tx an orphan
///     (Reject::missing_inputs): it waits in a bounded orphan set (100 txs,
///     20 minutes: Core DEFAULT_MAX_ORPHAN_TRANSACTIONS, ORPHAN_TX_EXPIRE_TIME)
///     and is admitted when its parent is admitted or confirmed. A partial
///     (accrual) view cannot tell an unknown coin from a spent one: there the
///     tx is admitted fee-unknown as before.
/// Selection takes only priced txs, and nothing without a view.

#include "block.hpp"
#include "transaction.hpp"

#include <core/uint256.hpp>
#include <core/pack.hpp>
#include <core/hash.hpp>
#include <core/log.hpp>
#include <core/coin/utxo_view_cache.hpp>

#include <nlohmann/json.hpp>

#include <algorithm>
#include <atomic>
#include <deque>
#include <limits>
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

/// Compute the txid as litecoind does (CTransaction::ComputeHash): an
/// MWEB-only tx is identified by its first kernel id; any other tx by the
/// SHA256d of its serialization without witness and MWEB data.
inline uint256 compute_txid(const MutableTransaction& tx) {
    if (tx.IsMWEBOnly()) {
        auto mw = mweb_wire::summarize_mw_transaction(tx.mweb_tx_raw);
        if (mw && !mw->kernels.empty())
            return mw->kernels.front().kernel_id;
    }
    auto packed = pack(TX_NO_WITNESS(tx));
    return Hash(packed.get_span());
}

/// Compute the wtxid as litecoind does (CTransaction::ComputeWitnessHash):
/// the txid when there is no witness, else the SHA256d of the serialization
/// with witness and without MWEB data.
inline uint256 compute_wtxid(const MutableTransaction& tx) {
    if (!tx.HasWitness())
        return compute_txid(tx);
    auto packed = pack(TX_WTXID(tx));
    return Hash(packed.get_span());
}

/// Compute BIP 141 weight: base_size*4 + witness_size.
/// base_size = legacy serialized bytes; full_size = with-witness bytes; both
/// without MWEB data (litecoind GetTransactionWeight).
inline void compute_tx_weight(const MutableTransaction& tx,
                               uint32_t& base_size,
                               uint32_t& witness_size,
                               uint32_t& weight)
{
    auto legacy = pack(TX_NO_WITNESS(tx));
    auto full   = pack(TX_WTXID(tx));
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
    /// A height of 0 is ignored: it never means the tip, and a tip of 0
    /// turns the maturity checks off (a body the caller could not place must
    /// not make every coinbase spendable).
    void set_tip_height(uint32_t h) {
        if (h != 0)
            m_tip_height = h;
    }
    uint32_t tip_height() const { return m_tip_height; }
    void set_utxo(core::coin::UTXOViewCache* u) { m_utxo.store(u); }

    // Disable copy
    Mempool(const Mempool&) = delete;
    Mempool& operator=(const Mempool&) = delete;

    // ─── Admission ───────────────────────────────────────────────────────

    /// Why admit() refused a transaction.
    struct Reject {
        enum Code {
            mweb_only,               // MWEB-to-MWEB (no canonical data, no peg kernel)
            mweb_pegin,              // a PEGIN kernel or a pegin output
            mweb_pegout,             // a PEGOUT kernel
            mweb_mixed,              // canonical data and an MWEB part, no peg
            pegin_output_no_kernel,  // a pegin output (OP_9 PUSH32) without an MWEB part
            vin_empty,
            vout_empty,
            hogex,                   // a HogEx outside a block
            malformed,               // an MWEB part that does not walk
            duplicate,               // already in the pool
            inputs_invalid,          // premature coinbase/pegout spend, money range, outputs above inputs
            missing_inputs,          // an input in neither the set nor the pool: parked as an orphan
            count
        };
        Code     code{malformed};
        uint256  txid;               // litecoind's txid (an MWEB-only tx: its kernel id)
        uint256  kernel_id;          // first kernel of the MWEB part (raw bytes), if any
        int64_t  mweb_fee{0};        // kernel fees of the MWEB part
        size_t   n_pegins{0};
    };

    static const char* reject_code_name(Reject::Code c) {
        switch (c) {
            case Reject::mweb_only:              return "mweb_only";
            case Reject::mweb_pegin:             return "mweb_pegin";
            case Reject::mweb_pegout:            return "mweb_pegout";
            case Reject::mweb_mixed:             return "mweb_mixed";
            case Reject::pegin_output_no_kernel: return "pegin_output_no_kernel";
            case Reject::vin_empty:              return "vin_empty";
            case Reject::vout_empty:             return "vout_empty";
            case Reject::hogex:                  return "hogex";
            case Reject::malformed:              return "malformed";
            case Reject::duplicate:              return "duplicate";
            case Reject::inputs_invalid:         return "inputs_invalid";
            case Reject::missing_inputs:         return "missing_inputs";
            case Reject::count:                  break;
        }
        return "unknown";
    }

    /// Admission counters (lock-free reads for the stats endpoint).
    struct RejectStats {
        std::atomic<uint64_t> by_code[Reject::count] = {};
        std::atomic<uint64_t> admitted{0};
        std::atomic<uint64_t> mweb_txs_seen{0};         // deliveries of txs with an MWEB part
        std::atomic<uint64_t> mweb_fee_skipped_sat{0};  // their kernel fees
        std::atomic<uint64_t> pegins_seen{0};           // peg-in kernels among them
        std::atomic<uint64_t> pegouts_seen{0};          // peg-out coins among them
        std::atomic<uint64_t> template_tx_dropped{0};   // admitted txs a template still refused
        std::atomic<uint64_t> orphans_promoted{0};      // orphans admitted once their parent was
        std::atomic<uint64_t> orphans_dropped{0};       // orphans expired, evicted or too large
    };

    /// Orphan set bounds (Dogecoin Core 1.14 net_processing.cpp / net_processing.h).
    static constexpr size_t   MAX_ORPHANS = 100;              // DEFAULT_MAX_ORPHAN_TRANSACTIONS
    static constexpr time_t   ORPHAN_EXPIRE_SECS = 20 * 60;   // ORPHAN_TX_EXPIRE_TIME
    static constexpr uint32_t MAX_ORPHAN_WEIGHT = 400'000;    // MAX_STANDARD_TX_WEIGHT

    /// Admit `tx` (nullopt) or say why not, checking in this order: empty vin
    /// or vout unless MWEB-only (CheckTransaction), a HogEx, an MWEB part, a
    /// pegin output without one (litecoind PreChecks refuses each of these);
    /// then the pool's own duplicate check; then, with a view, the inputs
    /// (inputs_invalid; missing_inputs parks the tx as an orphan when the
    /// view is built from genesis). Fees are computed as add_tx does. An
    /// admitted tx admits the orphans waiting for it.
    std::optional<Reject> admit(const MutableTransaction& tx, core::coin::UTXOViewCache* utxo) {
        auto r = admit_one(tx, utxo, /*count=*/true);
        if (!r && utxo)
            promote_orphans_of(compute_txid(tx), utxo);
        return r;
    }

private:
    std::optional<Reject> admit_one(const MutableTransaction& tx, core::coin::UTXOViewCache* utxo,
                                    bool count) {
        Reject r;
        r.txid = compute_txid(tx);
        auto refuse = [&](Reject::Code c) -> std::optional<Reject> {
            r.code = c;
            if (count)
                m_stats.by_code[c].fetch_add(1, std::memory_order_relaxed);
            return r;
        };

        if (!tx.IsMWEBOnly()) {
            if (tx.vin.empty())
                return refuse(Reject::vin_empty);
            if (tx.vout.empty())
                return refuse(Reject::vout_empty);
        }
        if (tx.m_hogEx)
            return refuse(Reject::hogex);

        bool pegin_output = false;
        for (const auto& out : tx.vout)
            pegin_output = pegin_output || mweb_wire::pegin_kernel_of(out.scriptPubKey).has_value();

        if (tx.HasMWEBTx()) {
            m_stats.mweb_txs_seen.fetch_add(1, std::memory_order_relaxed);
            auto mw = mweb_wire::summarize_mw_transaction(tx.mweb_tx_raw);
            if (!mw)
                return refuse(Reject::malformed);
            r.kernel_id = mw->kernels.front().kernel_id;
            r.mweb_fee = mw->total_fee();
            r.n_pegins = mw->n_pegins();
            m_stats.mweb_fee_skipped_sat.fetch_add(static_cast<uint64_t>(r.mweb_fee),
                                                   std::memory_order_relaxed);
            m_stats.pegins_seen.fetch_add(r.n_pegins, std::memory_order_relaxed);
            m_stats.pegouts_seen.fetch_add(mw->n_pegouts(), std::memory_order_relaxed);
            if (mw->has_pegin() || pegin_output)
                return refuse(Reject::mweb_pegin);
            if (mw->has_pegout())
                return refuse(Reject::mweb_pegout);
            return refuse(tx.IsMWEBOnly() ? Reject::mweb_only : Reject::mweb_mixed);
        }
        if (pegin_output)
            return refuse(Reject::pegin_output_no_kernel);

        if (utxo) {
            std::lock_guard<std::mutex> lock(m_mutex);
            if (m_pool.count(r.txid))
                return refuse(Reject::duplicate);
            std::vector<uint256> missing;
            switch (check_inputs_locked(tx, utxo, missing)) {
            case Inputs::Ok:
                break;
            case Inputs::Invalid:
                erase_orphan_locked(r.txid);
                return refuse(Reject::inputs_invalid);
            case Inputs::Missing:
                // Only a set built from genesis knows the input is not there:
                // a partial view admits the tx fee-unknown, as before.
                if (utxo->anchor_height() == 0) {
                    park_orphan_locked(tx, r.txid, missing);
                    return refuse(Reject::missing_inputs);
                }
                break;
            }
        }

        if (!add_tx_unchecked(tx, utxo))
            return refuse(Reject::duplicate);
        if (count)
            m_stats.admitted.fetch_add(1, std::memory_order_relaxed);
        if (utxo)
            reprice_children(r.txid, utxo);
        return std::nullopt;
    }

    /// The pool's unpriced children of `parent` (admitted before it) are
    /// priced now, and theirs in turn, instead of at the next block.
    void reprice_children(const uint256& parent, core::coin::UTXOViewCache* utxo) {
        std::lock_guard<std::mutex> lock(m_mutex);
        std::deque<uint256> work{parent};
        while (!work.empty()) {
            const uint256 p = work.front();
            work.pop_front();
            auto pit = m_pool.find(p);
            if (pit == m_pool.end())
                continue;
            const auto n_out = static_cast<uint32_t>(pit->second.tx.vout.size());
            for (uint32_t i = 0; i < n_out; ++i) {
                auto so = m_spent_outputs.find(std::make_pair(p, i));
                if (so == m_spent_outputs.end())
                    continue;
                auto cit = m_pool.find(so->second);
                if (cit == m_pool.end() || cit->second.fee_known)
                    continue;
                if (compute_fee_locked(cit->second, utxo)) {
                    m_feerate_index.emplace(cit->second.feerate(), cit->first);
                    work.push_back(cit->first);
                }
            }
        }
    }

public:
    const RejectStats& reject_stats() const { return m_stats; }

    /// Orphans waiting for a parent.
    size_t orphan_count() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_orphans.size();
    }

    bool is_orphan(const uint256& txid) const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_orphans.count(txid) > 0;
    }

    /// The view the template prices against (null: none; nothing is selected).
    core::coin::UTXOViewCache* utxo() const { return m_utxo.load(); }

    /// Admit the orphans whose missing parents are now in the view or the
    /// pool (a block confirmed them); drop the expired ones. An orphan still
    /// missing an input keeps its place and its expiry. Returns how many were
    /// admitted. recompute_unknown_fees runs it after every block.
    int retry_orphans(core::coin::UTXOViewCache* utxo) {
        if (!utxo)
            return 0;
        std::vector<std::pair<uint256, MutableTransaction>> ready;
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            expire_orphans_locked(std::time(nullptr));
            ready = take_resolved_orphans_locked(all_orphans_locked(), utxo);
        }
        int admitted = 0;
        for (const auto& [txid, tx] : ready) {
            if (!admit_one(tx, utxo, /*count=*/false)) {
                ++admitted;
                m_stats.orphans_promoted.fetch_add(1, std::memory_order_relaxed);
                admitted += promote_orphans_of(txid, utxo);
            }
        }
        return admitted;
    }

    /// {"admitted", "rejected": {code: n}, "mweb_txs_seen", "mweb_fee_skipped_sat",
    ///  "pegins_seen", "pegouts_seen", "template_tx_dropped", "orphans",
    ///  "orphans_promoted", "orphans_dropped"}
    nlohmann::json reject_stats_json() const {
        nlohmann::json rejected = nlohmann::json::object();
        for (int c = 0; c < Reject::count; ++c)
            rejected[reject_code_name(static_cast<Reject::Code>(c))] =
                m_stats.by_code[c].load(std::memory_order_relaxed);
        return {
            {"admitted", m_stats.admitted.load(std::memory_order_relaxed)},
            {"rejected", std::move(rejected)},
            {"mweb_txs_seen", m_stats.mweb_txs_seen.load(std::memory_order_relaxed)},
            {"mweb_fee_skipped_sat", m_stats.mweb_fee_skipped_sat.load(std::memory_order_relaxed)},
            {"pegins_seen", m_stats.pegins_seen.load(std::memory_order_relaxed)},
            {"pegouts_seen", m_stats.pegouts_seen.load(std::memory_order_relaxed)},
            {"template_tx_dropped", m_stats.template_tx_dropped.load(std::memory_order_relaxed)},
            {"orphans", orphan_count()},
            {"orphans_promoted", m_stats.orphans_promoted.load(std::memory_order_relaxed)},
            {"orphans_dropped", m_stats.orphans_dropped.load(std::memory_order_relaxed)},
        };
    }

    // ─── Mutation ────────────────────────────────────────────────────────

    /// Add a transaction to the pool (no fee computation).
    /// Returns false if refused (admit) or already known.
    bool add_tx(const MutableTransaction& tx) {
        return add_tx(tx, nullptr);
    }

    /// Add a transaction to the pool with optional UTXO-based fee computation
    /// (admit() without the reason).
    bool add_tx(const MutableTransaction& tx, core::coin::UTXOViewCache* utxo) {
        return !admit(tx, utxo);
    }

    /// Add a transaction WITHOUT the admission rules (tests of the template
    /// side's own checks; production code uses add_tx / admit).
    /// When utxo is non-null, computes fee = sum(input_values) - sum(output_values).
    /// Falls back to fee_known=false if any input is missing from the UTXO set
    /// or from a parent mempool transaction (chain-of-unconfirmed / CPFP).
    /// Returns false if the txid is already in the pool.
    bool add_tx_unchecked(const MutableTransaction& tx, core::coin::UTXOViewCache* utxo = nullptr) {
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
        const uint256 block_hash = Hash(pack(static_cast<const BlockHeaderType&>(block)).get_span());
        std::lock_guard<std::mutex> lock(m_mutex);
        int removed = 0, conflicts = 0;
        note_block_cleaned_locked(block_hash);
        erase_orphans_for_block_locked(block);

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
        m_orphans.clear();
        m_orphans_by_parent.clear();
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

    /// Wire bytes of the priced (fee_known) transactions: what a selection
    /// can take, as TemplateBuilder counts a selected tx (base + witness).
    /// An unpriced (quarantined) tx enters no template.
    uint64_t priced_bytes() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        uint64_t sum = 0;
        for (const auto& [txid, entry] : m_pool) {
            if (entry.fee_known)
                sum += uint64_t{entry.base_size} + entry.witness_size;
        }
        return sum;
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

    /// Header hash of the last block remove_for_block() ran for (null = none).
    uint256 last_block_hash() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_last_block_hash;
    }

    /// True when remove_for_block() ran for `block_hash` (one of the last
    /// CLEANED_BLOCKS_KEPT blocks it saw): the txs that block confirmed are
    /// gone. Late copies of an older block or a stale sibling's body also run
    /// through remove_for_block after the tip's, so the tip need not be the
    /// last one.
    bool cleaned_for(const uint256& block_hash) const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return std::find(m_cleaned_blocks.begin(), m_cleaned_blocks.end(), block_hash)
            != m_cleaned_blocks.end();
    }

    /// Unix time of the last remove_for_block() (0 = never).
    time_t last_cleaned_time() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_last_cleaned_time;
    }

    /// What a block transaction may be: inputs and outputs, no MWEB part,
    /// not a HogEx, no pegin output (the template side of admit()'s rules).
    static bool block_can_carry(const MutableTransaction& tx) {
        if (tx.vin.empty() || tx.vout.empty() || tx.HasMWEBTx() || tx.m_hogEx)
            return false;
        for (const auto& out : tx.vout)
            if (mweb_wire::pegin_kernel_of(out.scriptPubKey))
                return false;
        return true;
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
    /// Only priced (fee_known) transactions are selected: with a view built
    /// from genesis an unpriced tx is an orphan, a premature spend or a
    /// money-range failure, none of which may enter a block. No view, no
    /// selection: nothing can be shown to spend an unspent coin.
    /// Returns total_fees across all selected transactions.
    ///
    /// #1437 — template validity: the selected set MUST be a self-consistent
    /// block body or the daemon rejects the whole template
    /// (bad-txns-inputs-missingorspent) and the found block is LOST. Two hazards
    /// the naive highest-feerate-first pass admits:
    ///   (a) child-without-parent — an input funded by another MEMPOOL tx (the
    ///       parent) selected AFTER the child, or not selected at all. A block
    ///       must place every parent before its children; a CPFP child normally
    ///       out-feerates its parent, so pure feerate order emits the child
    ///       first. Fix: a tx is admissible only once every one of its in-
    ///       mempool parents is already selected (parents-before-children), and
    ///       a fixed-point re-scan lets the high-feerate child still land in a
    ///       later pass — never dropped, never mis-ordered.
    ///   (b) intra-template double-spend — m_spent_outputs keeps only the LAST
    ///       writer per outpoint, so two mempool txs spending the same outpoint
    ///       both stay selectable. An outpoint may be spent by at most one tx in
    ///       a block. Fix: a per-template consumed-outpoint set (shared across
    ///       both passes) refuses the second spender.
    /// Reward-neutral: total_fees sums only INCLUDED txs' known fees, so
    /// coinbasevalue tracks exactly the txs that ship.
    std::pair<std::vector<SelectedTx>, uint64_t>
    get_sorted_txs_with_fees(uint32_t max_weight) const {
        std::lock_guard<std::mutex> lock(m_mutex);

        std::vector<SelectedTx> result;
        uint64_t total_fees = 0;
        uint32_t total_weight = 0;
        std::set<uint256> selected;
        // Per-template consumed outpoints: one entry per input of every
        // selected tx, so no outpoint is spent twice.
        std::set<std::pair<uint256, uint32_t>> consumed;

        auto* utxo = m_utxo.load();
        if (!utxo)
            return {std::move(result), total_fees};  // no view, no selection

        // Belt under admit(): a tx no block can carry never joins a template,
        // however it reached the pool. Counted per template; expected 0.
        std::set<uint256> barred;
        for (const auto& [txid, entry] : m_pool)
            if (!block_can_carry(entry.tx))
                barred.insert(txid);
        if (!barred.empty()) {
            m_stats.template_tx_dropped.fetch_add(barred.size(), std::memory_order_relaxed);
            LOG_WARNING << "[EMB] Mempool: " << barred.size()
                        << " tx(s) no block can carry kept out of the template";
        }

        // Can `entry` join the template given the current selection state?
        //   - refuse if any input outpoint is already consumed (double-spend)
        //   - if an input is funded by another MEMPOOL tx (parent), that parent
        //     must already be selected (topological: parents before children);
        //     otherwise defer — a later fixed-point pass admits it once the
        //     parent lands.
        //   - an input in neither the UTXO set nor a mempool parent is
        //     stale/orphan — refuse.
        auto admissible = [&](const MempoolEntry& entry) -> bool {
            if (barred.count(entry.txid))
                return false;
            for (const auto& vin : entry.tx.vin) {
                std::pair<uint256, uint32_t> op(vin.prevout.hash, vin.prevout.index);
                if (consumed.count(op)) return false;  // intra-template double-spend

                auto parent = m_pool.find(vin.prevout.hash);
                const bool has_mempool_parent =
                    parent != m_pool.end() &&
                    vin.prevout.index < parent->second.tx.vout.size();

                if (has_mempool_parent) {
                    if (!selected.count(vin.prevout.hash))
                        return false;  // parent not yet in template — defer
                } else {
                    core::coin::Outpoint uop(vin.prevout.hash, vin.prevout.index);
                    core::coin::Coin coin;
                    if (!utxo->get_coin(uop, coin))
                        return false;  // absent from UTXO and mempool — stale
                    // Not spendable in the block being built (height tip + 1).
                    if (m_tip_height > 0 && !coin.is_mature(m_tip_height + 1, m_limits))
                        return false;
                }
            }
            return true;
        };

        // Pass 1: fixed-point selection over the feerate index (highest first).
        // Each pass admits every currently-admissible fee-known tx; passes
        // repeat until one adds nothing, so a high-feerate CPFP child admitted
        // only after its lower-feerate parent still lands — parent first, never
        // dropped. Bounded by the tx count (each pass adds ≥1 or terminates).
        bool progress = true;
        while (progress) {
            progress = false;
            for (auto it = m_feerate_index.begin(); it != m_feerate_index.end(); ++it) {
                if (selected.count(it->second)) continue;  // already in template
                auto pit = m_pool.find(it->second);
                if (pit == m_pool.end()) continue;
                const auto& entry = pit->second;
                if (!entry.fee_known) continue;
                if (total_weight + entry.weight > max_weight) continue;
                if (!admissible(entry)) continue;

                total_weight += entry.weight;
                total_fees += entry.fee;
                result.push_back({entry.tx, entry.fee, true});
                selected.insert(entry.txid);
                for (const auto& vin : entry.tx.vin)
                    consumed.emplace(vin.prevout.hash, vin.prevout.index);
                progress = true;
            }
        }

        return {std::move(result), total_fees};
    }

    /// Re-attempt fee computation for all transactions with fee_known=false,
    /// then admit the orphans whose parents a block confirmed.
    /// With a set built from genesis (anchor 0) an entry that still cannot
    /// be priced leaves the pool as admit() would treat it now: an input in
    /// neither the set nor the pool -> the orphan set; an invalid input
    /// (premature spend, money range) -> dropped. The pool then holds priced
    /// txs only (the one exception: a coinbase spend mature at the next
    /// height but not at the tip, priced at the next block).
    /// Call after a new block is connected (new UTXOs may resolve missing inputs).
    /// Returns the number of transactions whose fees were successfully computed.
    int recompute_unknown_fees(core::coin::UTXOViewCache* utxo) {
        if (!utxo) return 0;
        const int promoted = retry_orphans(utxo);
        const bool full_view = utxo->anchor_height() == 0;
        std::lock_guard<std::mutex> lock(m_mutex);
        int resolved = 0;
        int still_unknown = 0;
        int parked = 0;
        int dropped = 0;
        uint64_t resolved_total_fee = 0;
        std::vector<std::pair<uint256, Inputs>> unpriced;
        std::vector<std::vector<uint256>> missing_of;
        for (auto& [txid, entry] : m_pool) {
            if (entry.fee_known) continue;
            if (compute_fee_locked(entry, utxo)) {
                m_feerate_index.emplace(entry.feerate(), txid);
                resolved_total_fee += entry.fee;
                ++resolved;
                continue;
            }
            if (full_view) {
                std::vector<uint256> missing;
                const Inputs in = check_inputs_locked(entry.tx, utxo, missing);
                if (in != Inputs::Ok) {
                    unpriced.emplace_back(txid, in);
                    missing_of.push_back(std::move(missing));
                    continue;
                }
            }
            ++still_unknown;
        }
        for (size_t i = 0; i < unpriced.size(); ++i) {
            const auto& [txid, in] = unpriced[i];
            auto it = m_pool.find(txid);
            if (it == m_pool.end())
                continue;
            const MutableTransaction tx = it->second.tx;
            remove_tx_locked(txid);
            if (in == Inputs::Missing) {
                park_orphan_locked(tx, txid, missing_of[i]);
                ++parked;
            } else {
                ++dropped;
            }
        }
        // Every block runs this (and every copy of a body did): log when
        // something moved or the counts changed, not the same line again.
        const bool moved = resolved > 0 || promoted > 0 || parked > 0 || dropped > 0;
        const bool changed = still_unknown != m_last_logged_unknown
                          || m_orphans.size() != m_last_logged_orphans;
        m_last_logged_unknown = still_unknown;
        m_last_logged_orphans = m_orphans.size();
        if (moved || changed) {
            LOG_INFO << "[EMB] Mempool fee revalidation: resolved=" << resolved
                     << " still_unknown=" << still_unknown
                     << " resolved_fees=" << resolved_total_fee << " sat"
                     << " pool_size=" << m_pool.size()
                     << " orphans=" << m_orphans.size()
                     << " orphans_promoted=" << promoted
                     << (parked > 0 ? " parked=" + std::to_string(parked) : std::string())
                     << (dropped > 0 ? " dropped_invalid=" + std::to_string(dropped) : std::string());
        }
        return resolved;
    }

    /// Mark every transaction fee-unknown (quarantined): revalidate_inputs
    /// skips it and recompute_unknown_fees prices it again from the UTXO set.
    /// For a UTXO set that was wiped and is being rebuilt: an input missing
    /// from the refilling set is not yet reconnected, not spent, so a priced
    /// transaction must not be evicted for it. Same as BIP110's
    /// Mempool::requarantine_all after a reorg. Returns how many were priced.
    int requarantine_all() {
        std::lock_guard<std::mutex> lock(m_mutex);
        int n = 0;
        for (auto& [txid, entry] : m_pool) {
            if (entry.fee_known)
                ++n;
            entry.fee_known = false;
            entry.fee = 0;
        }
        m_feerate_index.clear();
        return n;
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
        std::vector<uint256> to_unprice;
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
                // Priced while the tip height was wrong: a coinbase (pegout)
                // spend not mature at the tip loses its price until it is.
                if (m_tip_height > 0 && !coin.is_mature(m_tip_height, m_limits)) {
                    to_unprice.push_back(txid);
                    break;
                }
            }
        }

        for (const auto& txid : to_remove)
            remove_tx_locked(txid);
        for (const auto& txid : to_unprice)
            unprice_locked(txid);
        if (!to_unprice.empty()) {
            LOG_WARNING << "[EMB] Mempool revalidate: " << to_unprice.size()
                        << " priced tx(s) spend a coinbase not mature at h=" << m_tip_height.load() << ": unpriced";
        }

        if (!to_remove.empty()) {
            LOG_INFO << "[EMB] Mempool revalidate: evicted " << to_remove.size()
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

    /// Return all transactions keyed by wtxid (BIP 152 v2 compact block reconstruction).
    std::map<uint256, MutableTransaction> all_txs_map_wtxid() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        std::map<uint256, MutableTransaction> out;
        for (const auto& [txid, entry] : m_pool)
            out[compute_wtxid(entry.tx)] = entry.tx;
        return out;
    }

    // ─── Lightweight snapshot for explorer API ───────────────────────────

    /// Lightweight entry metadata (no MutableTransaction copy).
    struct MempoolEntrySummary {
        uint256  txid;
        uint32_t base_size{0};
        uint32_t weight{0};
        uint64_t fee{0};
        bool     fee_known{false};
        time_t   time_added{0};
        uint32_t n_vin{0};
        uint32_t n_vout{0};
        double feerate() const {
            uint32_t vsize = (weight + 3) / 4;
            return (fee_known && vsize > 0) ? static_cast<double>(fee) / vsize : 0.0;
        }
    };

    /// Aggregate mempool statistics + sorted entry list.
    struct MempoolSummary {
        size_t   tx_count{0};
        size_t   total_bytes{0};
        uint64_t total_fees{0};
        uint32_t total_weight{0};
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
            es.base_size  = e.base_size;
            es.weight     = e.weight;
            es.fee        = e.fee;
            es.fee_known  = e.fee_known;
            es.time_added = e.time_added;
            es.n_vin      = static_cast<uint32_t>(e.tx.vin.size());
            es.n_vout     = static_cast<uint32_t>(e.tx.vout.size());
            s.total_weight += e.weight;
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

    /// What check_inputs_locked found.
    enum class Inputs { Ok, Missing, Invalid };

    /// Core HaveInputs + CheckTxInputs against the view and the pool: every
    /// input in the view or an in-pool parent (else Missing, with the missing
    /// parents' txids); a view coin mature at the next block's height (Core
    /// GetSpendHeight = tip + 1) and in money range; inputs cover outputs.
    Inputs check_inputs_locked(const MutableTransaction& tx, core::coin::UTXOViewCache* utxo,
                               std::vector<uint256>& missing) const {
        int64_t value_in = 0;
        for (const auto& vin : tx.vin) {
            core::coin::Outpoint op(vin.prevout.hash, vin.prevout.index);
            core::coin::Coin coin;
            int64_t v = 0;
            if (utxo->get_coin(op, coin)) {
                if (m_tip_height > 0 && !coin.is_mature(m_tip_height + 1, m_limits))
                    return Inputs::Invalid;  // bad-txns-premature-spend-of-coinbase
                v = coin.value;
            } else {
                auto parent = m_pool.find(vin.prevout.hash);
                if (parent == m_pool.end() || vin.prevout.index >= parent->second.tx.vout.size()) {
                    if (std::find(missing.begin(), missing.end(), vin.prevout.hash) == missing.end())
                        missing.push_back(vin.prevout.hash);
                    continue;
                }
                v = parent->second.tx.vout[vin.prevout.index].value;
            }
            if (!core::coin::money_range(v, m_limits))
                return Inputs::Invalid;  // bad-txns-inputvalues-outofrange
            value_in += v;
            if (!core::coin::money_range(value_in, m_limits))
                return Inputs::Invalid;
        }
        if (!missing.empty())
            return Inputs::Missing;
        int64_t value_out = 0;
        for (const auto& vout : tx.vout) {
            if (!core::coin::money_range(vout.value, m_limits))
                return Inputs::Invalid;  // bad-txns-vout-toolarge / negative
            value_out += vout.value;
            if (!core::coin::money_range(value_out, m_limits))
                return Inputs::Invalid;
        }
        if (value_in < value_out)
            return Inputs::Invalid;  // bad-txns-in-belowout
        return Inputs::Ok;
    }

    struct Orphan {
        MutableTransaction   tx;
        time_t               time_added{0};
        std::vector<uint256> parents;  // the missing parents' txids
    };

    void park_orphan_locked(const MutableTransaction& tx, const uint256& txid,
                            const std::vector<uint256>& parents) {
        if (m_orphans.count(txid))
            return;
        uint32_t base_size = 0, witness_size = 0, weight = 0;
        compute_tx_weight(tx, base_size, witness_size, weight);
        if (weight >= MAX_ORPHAN_WEIGHT) {
            m_stats.orphans_dropped.fetch_add(1, std::memory_order_relaxed);
            return;  // Core AddOrphanTx: ignoring large orphan
        }
        const time_t now = std::time(nullptr);
        expire_orphans_locked(now);
        while (m_orphans.size() >= MAX_ORPHANS) {
            // Core evicts a random orphan; the oldest goes here.
            auto oldest = m_orphans.begin();
            for (auto it = m_orphans.begin(); it != m_orphans.end(); ++it)
                if (it->second.time_added < oldest->second.time_added)
                    oldest = it;
            erase_orphan_locked(oldest->first);
            m_stats.orphans_dropped.fetch_add(1, std::memory_order_relaxed);
        }
        Orphan o;
        o.tx = tx;
        o.time_added = now;
        o.parents = parents;
        for (const auto& p : parents)
            m_orphans_by_parent.emplace(p, txid);
        m_orphans.emplace(txid, std::move(o));
    }

    void erase_orphan_locked(const uint256& txid) {
        auto it = m_orphans.find(txid);
        if (it == m_orphans.end())
            return;
        for (const auto& p : it->second.parents) {
            auto range = m_orphans_by_parent.equal_range(p);
            for (auto b = range.first; b != range.second;) {
                if (b->second == txid)
                    b = m_orphans_by_parent.erase(b);
                else
                    ++b;
            }
        }
        m_orphans.erase(it);
    }

    void expire_orphans_locked(time_t now) {
        std::vector<uint256> old;
        for (const auto& [txid, o] : m_orphans)
            if (o.time_added + ORPHAN_EXPIRE_SECS <= now)
                old.push_back(txid);
        for (const auto& txid : old) {
            erase_orphan_locked(txid);
            m_stats.orphans_dropped.fetch_add(1, std::memory_order_relaxed);
        }
    }

    /// A block confirmed or spent what an orphan would: drop it (Core
    /// erases the orphans a block includes or precludes).
    void erase_orphans_for_block_locked(const BlockType& block) {
        if (m_orphans.empty())
            return;
        std::set<std::pair<uint256, uint32_t>> spent;
        std::set<uint256> in_block;
        for (const auto& mtx : block.m_txs) {
            in_block.insert(compute_txid(mtx));
            for (const auto& vin : mtx.vin)
                spent.emplace(vin.prevout.hash, vin.prevout.index);
        }
        std::vector<uint256> gone;
        for (const auto& [txid, o] : m_orphans) {
            bool drop = in_block.count(txid) > 0;
            for (const auto& vin : o.tx.vin)
                drop = drop || spent.count({vin.prevout.hash, vin.prevout.index}) > 0;
            if (drop)
                gone.push_back(txid);
        }
        for (const auto& txid : gone)
            erase_orphan_locked(txid);
    }

    /// Every orphan's txid (caller holds the mutex).
    std::vector<uint256> all_orphans_locked() const {
        std::vector<uint256> all;
        all.reserve(m_orphans.size());
        for (const auto& [txid, o] : m_orphans)
            all.push_back(txid);
        return all;
    }

    /// Of `candidates`, take out of the orphan set those whose inputs now
    /// resolve (view or pool) or are invalid: admit_one decides about them.
    /// One still missing an input stays, with its expiry.
    std::vector<std::pair<uint256, MutableTransaction>>
    take_resolved_orphans_locked(const std::vector<uint256>& candidates, core::coin::UTXOViewCache* utxo) {
        std::vector<std::pair<uint256, MutableTransaction>> out;
        for (const auto& txid : candidates) {
            auto o = m_orphans.find(txid);
            if (o == m_orphans.end())
                continue;
            std::vector<uint256> missing;
            if (check_inputs_locked(o->second.tx, utxo, missing) == Inputs::Missing)
                continue;
            out.emplace_back(txid, o->second.tx);
            erase_orphan_locked(txid);
        }
        return out;
    }

    /// Admit the orphans waiting for `parent` (and theirs, in turn).
    /// Returns how many were admitted.
    int promote_orphans_of(const uint256& parent, core::coin::UTXOViewCache* utxo) {
        int admitted = 0;
        std::deque<uint256> work{parent};
        while (!work.empty()) {
            const uint256 p = work.front();
            work.pop_front();
            std::vector<std::pair<uint256, MutableTransaction>> waiting;
            {
                std::lock_guard<std::mutex> lock(m_mutex);
                std::vector<uint256> candidates;
                auto range = m_orphans_by_parent.equal_range(p);
                for (auto it = range.first; it != range.second; ++it)
                    candidates.push_back(it->second);
                waiting = take_resolved_orphans_locked(candidates, utxo);
            }
            for (const auto& [txid, tx] : waiting) {
                if (!admit_one(tx, utxo, /*count=*/false)) {
                    ++admitted;
                    m_stats.orphans_promoted.fetch_add(1, std::memory_order_relaxed);
                    work.push_back(txid);
                }
            }
        }
        return admitted;
    }

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

    /// Fee unknown again (out of the feerate index): never selected until
    /// recompute_unknown_fees prices it.
    void unprice_locked(const uint256& txid) {
        auto it = m_pool.find(txid);
        if (it == m_pool.end() || !it->second.fee_known)
            return;
        auto fr_range = m_feerate_index.equal_range(it->second.feerate());
        for (auto fi = fr_range.first; fi != fr_range.second; ++fi) {
            if (fi->second == txid) {
                m_feerate_index.erase(fi);
                break;
            }
        }
        it->second.fee_known = false;
        it->second.fee = 0;
    }

    void evict_one_locked(const uint256& txid) {
        remove_tx_locked(txid);
    }

    void note_block_cleaned_locked(const uint256& block_hash) {
        m_last_block_hash = block_hash;
        m_last_cleaned_time = std::time(nullptr);
        if (std::find(m_cleaned_blocks.begin(), m_cleaned_blocks.end(), block_hash)
                == m_cleaned_blocks.end()) {
            m_cleaned_blocks.push_back(block_hash);
            if (m_cleaned_blocks.size() > CLEANED_BLOCKS_KEPT)
                m_cleaned_blocks.pop_front();
        }
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

    /// Orphans (txid -> tx) and the parents they wait for (parent -> orphan).
    std::map<uint256, Orphan>        m_orphans;
    std::multimap<uint256, uint256>  m_orphans_by_parent;

    // The last "[EMB] Mempool fee revalidation" counts logged.
    int    m_last_logged_unknown{-1};
    size_t m_last_logged_orphans{0};

    size_t m_total_bytes{0};    // sum of base_size across all entries
    size_t m_max_bytes;
    time_t m_expiry_sec;
    core::coin::ChainLimits m_limits;   // MoneyRange + maturity constants
    std::atomic<uint32_t> m_tip_height{0};  // current chain tip (maturity); set from the io_context and the DOGE full set's thread
    std::atomic<core::coin::UTXOViewCache*> m_utxo{nullptr};  // for template-time input validation

    // Blocks remove_for_block() ran for (most recent last), for cleaned_for().
    static constexpr size_t CLEANED_BLOCKS_KEPT = 16;
    std::deque<uint256> m_cleaned_blocks;
    uint256 m_last_block_hash;
    time_t  m_last_cleaned_time{0};

    mutable RejectStats m_stats;   // template_tx_dropped counts in const selection
};

} // namespace coin
} // namespace ltc