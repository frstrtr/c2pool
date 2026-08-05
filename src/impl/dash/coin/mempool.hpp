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
///
/// ██ SOLE-INGESTION-PATH INVARIANT (audit N-A-BY-SOURCE-INVARIANT rows) ██
/// The ONLY path that feeds add_tx() in a live node is dashd-peer relay:
/// interfaces::Node::new_tx → wire_mempool_ingest (mempool_ingest.hpp) →
/// CoinStateMaintainer::on_mempool_tx → add_tx. Two whole ConnectBlock
/// reject classes are argued N-A on exactly this invariant
/// (DASH_CONNECTBLOCK_REJECT_SURFACE_AUDIT.md §6):
///   - bad-txns-nonfinal (BIP68/locktime): relay-admitted txs are final at
///     admission and finality is monotonic in height/MTP;
///   - mandatory-script-verify-flag (CheckInputScripts): relay-admitted txs
///     passed full script checks at every relaying dashd, and we never
///     mutate tx bytes.
/// If ANY other ingestion seam is ever added (RPC sendrawtransaction, local
/// wallet submission, cross-coin tx forward, BIP35 sync drain), those two
/// rows become GAPs: re-audit and add local finality + script checks BEFORE
/// wiring it. Do not silently add callers of add_tx().

#include "block.hpp"
#include "transaction.hpp"
#include "utxo_adapter.hpp"
#include "sigops.hpp"             // G2: bad-blk-sigops accounting during selection
#include "vendor/assetlock.hpp"   // DIP-0027 CAssetUnlockPayload (type-9 fee source)

#include <core/uint256.hpp>
#include <core/pack.hpp>
#include <core/hash.hpp>
#include <core/log.hpp>
#include <core/coin/utxo_view_cache.hpp>

#include <atomic>
#include <cstdint>
#include <ctime>
#include <deque>
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

        // G4: an outpoint spent by a CONFIRMED tx is resolved — whatever
        // islock claimed it is now enforced (or moot) by the chain itself, so
        // the tracking entry has done its job. Prune it.
        for (const auto& mtx : block.m_txs) {
            for (const auto& vin : mtx.vin) {
                m_islock_outpoints.erase(
                    std::make_pair(vin.prevout.hash, vin.prevout.index));
            }
        }

        if (removed > 0 || conflicts > 0) {
            LOG_INFO << "[MEMPOOL] block cleanup removed=" << removed
                     << " conflicts=" << conflicts
                     << " remaining=" << m_pool.size();
        }
    }

    // ── G4 (audit): InstantSend-lock conflict tracking ──────────────────
    /// Register an islock: `locked_txid` holds the exclusive InstantSend
    /// right to spend each outpoint in `inputs`. dashd rejects a block
    /// containing any tx that conflicts with a known islock
    /// (validation.cpp:2622 `conflict-tx-lock`), so the template builder
    /// must never pack such a tx. Two defences, mirroring dashd's own
    /// CInstantSendManager::RemoveConflictingLock posture:
    ///   1. eviction NOW: any pool entry already spending one of these
    ///      outpoints under a DIFFERENT txid is removed immediately;
    ///   2. selection guard: get_sorted_txs_with_fees() re-checks every
    ///      candidate vin against this map (belt for txs admitted between
    ///      islock arrival and eviction, and for re-added conflicts).
    ///
    /// RESIDUAL RACE (documented, not closable node-side): an islock that
    /// FORMS (or reaches us) after a template was emitted can invalidate a
    /// share won on that template — the islock-formation window. dashd's
    /// validator itself waives conflict-tx-lock once the block is
    /// chainlocked (validation.cpp:2612 has_chainlock override), so the
    /// exposure is one islock-vs-block race per conflicting spend, the same
    /// race dashd's own miner runs. There is no pre-emit oracle for "an
    /// islock will form for the OTHER spend"; tracking known locks is the
    /// full extent of what any miner can do.
    ///
    /// FEED: dashd-peer relay (the sole-ingestion-path invariant covers
    /// islocks too — they arrive from the same relay peers as the txs).
    /// Until the coin-P2P isdlock parse leg lands, this map stays empty and
    /// selection behaves exactly as before (empty map = no exclusions).
    void add_islock(const uint256& locked_txid,
                    const std::vector<std::pair<uint256, uint32_t>>& inputs)
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        for (const auto& in : inputs) {
            // Bound the tracking map (relay is untrusted input): evict the
            // oldest registration once over cap. 100k outpoints ≈ a few MB.
            while (m_islock_order.size() >= MAX_ISLOCK_OUTPOINTS
                   && !m_islock_order.empty()) {
                m_islock_outpoints.erase(m_islock_order.front());
                m_islock_order.pop_front();
            }
            auto [it, inserted] = m_islock_outpoints.insert_or_assign(
                in, locked_txid);
            if (inserted) m_islock_order.push_back(in);
            // Defence 1: evict a conflicting pool entry right away.
            auto sit = m_spent_outputs.find(in);
            if (sit != m_spent_outputs.end() && sit->second != locked_txid
                && m_pool.count(sit->second)) {
                LOG_INFO << "[MEMPOOL] evicting islock-conflicting tx "
                         << sit->second.GetHex().substr(0, 16)
                         << " (outpoint locked to "
                         << locked_txid.GetHex().substr(0, 16) << ")";
                remove_tx_locked(sit->second);
            }
        }
    }

    size_t islock_outpoint_count() const
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_islock_outpoints.size();
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
        m_islock_outpoints.clear();
        m_islock_order.clear();
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
    /// Returns transactions in TOPOLOGICALLY-VALID feerate order (see G1
    /// below) up to `max_bytes` of base-size budget. Transactions with
    /// unknown fees are EXCLUDED — they'd poison the coinbasevalue if we
    /// included them at fee=0 vs dashd's GBT (which always knows
    /// fees because it sees the full mempool with full UTXO).
    ///
    /// ── ConnectBlock reject-surface audit gaps closed here ─────────────
    /// (frstrtr/the docs/DASH_CONNECTBLOCK_REJECT_SURFACE_AUDIT.md §1)
    ///
    /// G1 `bad-txns-inputs-missingorspent` — TOPOLOGICAL selection. The
    ///   pre-fix selector walked the feerate index strictly descending, so a
    ///   CPFP child that out-feed its parent was packed BEFORE (or without)
    ///   the parent — a consensus-invalid block on a winning share. Now every
    ///   candidate is expanded to its ancestor PACKAGE (all unselected
    ///   in-mempool ancestors, parents-first); the whole package is admitted
    ///   atomically or the child is dropped. A vin is satisfied only by a
    ///   live UTXO coin or by a parent ALREADY IN THE SELECTED SET /
    ///   earlier in this package — never by bare mempool membership.
    ///
    /// G2 `bad-blk-sigops` — sigop accounting (sigops.hpp). Running
    ///   legacy+P2SH sigop count, seeded with dashd's 100-sigop coinbase
    ///   reserve; a package that would reach MaxBlockSigOps (40k) is
    ///   skipped, mirroring dashd miner TestPackage.
    ///
    /// G3 `bad-txns-premature-spend-of-coinbase` — coinbase maturity. When
    ///   the caller supplies `next_height`, a vin resolved from the UTXO
    ///   view must be mature at that height (Coin::is_mature, DASH_LIMITS
    ///   coinbase_maturity=100) or the package is dropped. `next_height==0`
    ///   (legacy callers) skips the check.
    ///
    /// G4 `conflict-tx-lock` — islock conflicts. A vin spending an outpoint
    ///   that a known islock assigns to a DIFFERENT txid drops the package
    ///   (see add_islock for the tracking + the documented residual race).
    ///
    /// Stale-input guard: re-checks each candidate's inputs against
    /// the live UTXO + selected-set parents before including. Catches
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

    /// dashd policy DEFAULT_ANCESTOR_LIMIT: a candidate whose in-mempool
    /// ancestor package exceeds this is dropped (unminable by dashd's own
    /// miner too — its mempool never admits deeper chains).
    static constexpr size_t MAX_PACKAGE_TXS = 25;

    // exclude_special (C-3): when true, drop every Dash special tx (tx.type != 0
    // — ProRegTx/ProUpServTx/asset-lock/asset-unlock) from the selection. dashd
    // recomputes the coinbase CbTx roots (merkleRootMNList/Quorums) and the
    // DIP-0027 creditPoolBalance by APPLYING the block's own special txs, so
    // including one in the embedded template WITHOUT folding its effect into the
    // CbTx yields bad-cbtx and a rejected block. build_embedded_workdata passes
    // true (safe-minimal: the creditPool accrual then reduces to the platform-
    // reward term only). Default false preserves the mempool's general pricing +
    // selection capability (including the asset-unlock fee path) unchanged.
    std::pair<std::vector<SelectedTx>, uint64_t>
    get_sorted_txs_with_fees(uint32_t max_bytes, bool exclude_special = false,
                             uint32_t next_height = 0) const
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        std::vector<SelectedTx> result;
        std::set<uint256> selected;   // G1: the parent-in-selected-set check
        uint64_t total_fees   = 0;
        uint32_t total_bytes  = 0;
        uint32_t total_sigops = DASH_COINBASE_SIGOPS_RESERVE;   // G2
        auto* utxo = m_utxo.load();

        for (const auto& fk : m_feerate_index) {
            const uint256& txid = fk.txid;
            if (selected.count(txid)) continue;  // packed earlier as an ancestor
            if (m_pool.find(txid) == m_pool.end()) continue;

            // ── G1: expand to the ancestor package, parents-first ────────
            std::vector<const MempoolEntry*> package;
            {
                std::set<uint256> seen;
                if (!collect_package_locked(txid, selected, seen, package, 0))
                    continue;   // over-deep / over-wide chain: drop candidate
            }

            // Package membership for intra-package vin resolution (a parent
            // earlier in `package` is as good as one already selected).
            std::set<uint256> in_package;
            for (const auto* e : package) in_package.insert(e->txid);

            // ── Validate the WHOLE package; any failing member drops the
            // candidate (never a partial package — that is exactly the
            // childless-parent / parentless-child shape G1 forbids). ──────
            bool     ok         = true;
            uint32_t pkg_bytes  = 0;
            uint64_t pkg_fees   = 0;
            uint32_t pkg_sigops = 0;
            for (const auto* e : package) {
                if (!e->fee_known) { ok = false; break; }
                if (exclude_special && e->tx.type != 0) { ok = false; break; }

                // G2: legacy sigops (every scriptSig + every scriptPubKey,
                // multisig = 20), exactly dashd GetLegacySigOpCount.
                uint32_t tx_sigops = 0;
                for (const auto& vout : e->tx.vout) {
                    tx_sigops += count_script_sigops(
                        vout.scriptPubKey.m_data, /*accurate=*/false);
                }

                for (const auto& vin : e->tx.vin) {
                    tx_sigops += count_script_sigops(
                        vin.scriptSig.m_data, /*accurate=*/false);

                    auto opkey = std::make_pair(vin.prevout.hash,
                                                vin.prevout.index);

                    // G4: islock conflict — the outpoint is locked to a
                    // different txid; packing this tx is conflict-tx-lock.
                    auto lk = m_islock_outpoints.find(opkey);
                    if (lk != m_islock_outpoints.end()
                        && lk->second != e->txid) {
                        ok = false;
                        break;
                    }

                    // Resolve the prevout: in-package/selected parent first
                    // (an in-mempool parent output can never be a coinbase,
                    // so no maturity question), then the live UTXO view.
                    auto parent = m_pool.find(vin.prevout.hash);
                    if (parent != m_pool.end()
                        && (in_package.count(vin.prevout.hash)
                            || selected.count(vin.prevout.hash))) {
                        if (vin.prevout.index
                                >= parent->second.tx.vout.size()) {
                            ok = false;
                            break;
                        }
                        const auto& pscript = parent->second.tx
                            .vout[vin.prevout.index].scriptPubKey.m_data;
                        if (is_p2sh_script(pscript)) {
                            tx_sigops += count_p2sh_sigops(
                                vin.scriptSig.m_data);
                        }
                        continue;
                    }
                    if (utxo) {
                        ::core::coin::Outpoint op(vin.prevout.hash,
                                                  vin.prevout.index);
                        ::core::coin::Coin coin;
                        if (!utxo->get_coin(op, coin)) {
                            // Stale input: neither selected-parent nor UTXO.
                            ok = false;
                            break;
                        }
                        // G3: coinbase maturity. dashd CheckTxInputs rejects
                        // a spend of a coinbase younger than 100 confs
                        // (bad-txns-premature-spend-of-coinbase); the Coin
                        // carries is_coinbase+height, so refuse here instead
                        // of shipping the reject. next_height==0 = legacy
                        // caller, check skipped.
                        if (next_height != 0
                            && !coin.is_mature(next_height, DASH_LIMITS)) {
                            ok = false;
                            break;
                        }
                        if (is_p2sh_script(coin.scriptPubKey.m_data)) {
                            tx_sigops += count_p2sh_sigops(
                                vin.scriptSig.m_data);
                        }
                        continue;
                    }
                    // No UTXO view attached (unit-test / cold-start): the
                    // pre-fix selector accepted the vin unchecked; keep that
                    // behaviour for non-mempool prevouts (topological order
                    // and sigop caps above still apply).
                }
                if (!ok) break;

                pkg_bytes  += e->base_size;
                pkg_fees   += e->fee;
                pkg_sigops += tx_sigops;
            }
            if (!ok) continue;

            // Byte cap: the whole package must fit; a parent that does not
            // fit drops the child with it (G1's byte-cap clause). `continue`
            // (not break) — a later, smaller candidate may still fit.
            if (total_bytes + pkg_bytes > max_bytes) continue;
            // G2: dashd miner TestPackage bound (>= — reject AT the cap).
            if (total_sigops + pkg_sigops >= DASH_MAX_BLOCK_SIGOPS) continue;

            for (const auto* e : package) {
                selected.insert(e->txid);
                total_bytes += e->base_size;
                total_fees  += e->fee;
                result.push_back({e->tx, e->fee, e->base_size});
            }
            total_sigops += pkg_sigops;
        }
        return {std::move(result), total_fees};
    }

private:
    // G4: bound on tracked islock outpoints (relay-fed, so untrusted input;
    // FIFO eviction beyond this — see add_islock).
    static constexpr size_t MAX_ISLOCK_OUTPOINTS = 100'000;

    mutable std::mutex                                 m_mutex;
    std::map<uint256, MempoolEntry>                    m_pool;
    std::multimap<time_t, uint256>                     m_time_index;
    std::map<std::pair<uint256, uint32_t>, uint256>    m_spent_outputs;
    // Step 2: feerate-sorted index. greater<double> means begin() =
    // highest feerate, so iteration is best-first.
    std::set<FeeKey>                                   m_feerate_index;
    // G4: outpoint → txid holding the InstantSend lock on it, plus FIFO
    // insertion order for bounded eviction.
    std::map<std::pair<uint256, uint32_t>, uint256>    m_islock_outpoints;
    std::deque<std::pair<uint256, uint32_t>>           m_islock_order;
    size_t                                             m_total_bytes{0};
    size_t                                             m_max_bytes;
    time_t                                             m_expiry_sec;
    std::atomic<::core::coin::UTXOViewCache*>          m_utxo{nullptr};

    /// G1: gather `txid` plus every UNSELECTED in-mempool ancestor into
    /// `out`, parents strictly before children (post-order DFS). `seen`
    /// de-duplicates diamond dependencies within one package. Returns false
    /// when the package exceeds MAX_PACKAGE_TXS (drop the candidate; such a
    /// chain is deeper than dashd's own mempool would admit). Caller must
    /// hold m_mutex. Recursion depth is bounded by MAX_PACKAGE_TXS.
    bool collect_package_locked(const uint256& txid,
                                const std::set<uint256>& already_selected,
                                std::set<uint256>& seen,
                                std::vector<const MempoolEntry*>& out,
                                size_t depth) const
    {
        if (depth > MAX_PACKAGE_TXS || out.size() >= MAX_PACKAGE_TXS)
            return false;
        auto it = m_pool.find(txid);
        if (it == m_pool.end()) return false;
        if (!seen.insert(txid).second) return true;  // already scheduled
        for (const auto& vin : it->second.tx.vin) {
            if (already_selected.count(vin.prevout.hash)) continue;
            if (m_pool.find(vin.prevout.hash) == m_pool.end()) continue;
            if (!collect_package_locked(vin.prevout.hash, already_selected,
                                        seen, out, depth + 1)) {
                return false;
            }
        }
        if (out.size() >= MAX_PACKAGE_TXS) return false;
        out.push_back(&it->second);
        return true;
    }

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