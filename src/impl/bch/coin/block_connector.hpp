// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once
// ---------------------------------------------------------------------------
// bch::coin::BlockConnector -- M5 full-block body.
//
// Slices 1-3 closed the FORWARD path: full_block --> header index connect -->
// BIP130 best-chain-gated mempool reconciliation, and (with a UTXO view wired)
// connect_block() + the Phase-4 stale-input sweep. But a UTXO view that only
// ever moves forward is wrong the moment the best chain switches branches: the
// old branch stays applied (its spends and its created coins linger), and the
// txs it confirmed are silently lost from the mempool. connect_block() already
// returned a BlockUndo on every connect -- and it was being DISCARDED. This
// slice retains it and closes the REORG / DISCONNECT leg.
//
// For each received block on_full_block performs:
//
//   0. REMEMBER. Cache the full block (bounded ring) so a later reorg can
//      re-walk the new branch forward without re-requesting it from the wire.
//
//   1. BLOCK-CONNECT. Hand the 80-byte header to HeaderChain::add_header
//      (idempotent for an already-known header). Header sync / reorg accounting
//      and best-tip selection by cumulative work live there, not here.
//
//   2. BIP130 BEST-CHAIN GATE. Only a block that IS the new best tip drives any
//      state change. A side / stale / orphan block leaves both the UTXO view
//      and the mempool untouched.
//
//   3. UTXO SYNC TO TIP (only when a UTXO view is wired):
//        - FORWARD EXTEND  (new tip's prev == our connected tip, or cold start):
//          connect_block() applies it; the BlockUndo is pushed on the undo stack.
//        - RE-DELIVERY     (new tip == our connected tip): no-op (idempotent).
//        - REORG           (new tip is on a different branch): walk our undo
//          stack back to the fork point, disconnect_block() each old-branch
//          block (restore spent inputs, remove created outputs) and return its
//          non-coinbase txs to the mempool, then connect_block() forward along
//          the new branch from the remembered-block cache up to the new tip.
//          A new-branch block not in the cache (reorg deeper than retained
//          history) leaves the view at the fork and logs for resync -- never a
//          silent half-applied UTXO set.
//
//   4. MEMPOOL RECONCILIATION to the new tip: set_tip_height + remove_for_block
//      (Phases 1-3, txid/outpoint) then, with a view, revalidate_inputs
//      (Phase 4) sweeps anything the connect left unspendable.
//
// THREADING: single-threaded use from the daemon's block-processing context.
//
// p2pool-merged-v36 SURFACE: NONE. Pure local block-connect + UTXO/mempool
// hygiene; no PoW hash, share format, coinbase commitment, AuxPoW, or PPLNS
// math is touched. PER-COIN ISOLATION: src/impl/bch/coin/ only; every type is
// bch-owned. Build-INERT / source-only header (bch stays skip-green).
// ---------------------------------------------------------------------------

#include "block.hpp"
#include "header_chain.hpp"     // bch::coin::block_hash(), HeaderChain, IndexEntry, Uint256Hasher
#include "mempool.hpp"          // Mempool, core::coin::UTXOViewCache
#include "node_interface.hpp"   // bch::interfaces::Node (full_block event)
#include "compact_blocks.hpp"  // CompactBlock, BlockTransactions{Request,Response}, ReconstructBlock

#include <core/coin/utxo.hpp>   // core::coin::BlockUndo
#include <core/events.hpp>      // EventDisposable
#include <core/uint256.hpp>
#include <core/log.hpp>

#include <deque>
#include <memory>
#include <optional>
#include <functional>
#include <unordered_map>
#include <vector>

namespace bch {
namespace coin {

/// Closes the full-block UTXO/mempool path: full_block --> header connect -->
/// best-chain-gated UTXO sync (forward + reorg) + mempool reconciliation.
/// Daemon-owned; the chain and pool it references must outlive it.
class BlockConnector {
public:
    /// @param chain  best-chain header index (connect target + tip authority).
    /// @param pool   mempool to reconcile against each best-chain tip change.
    BlockConnector(HeaderChain& chain, Mempool& pool)
        : m_chain(chain), m_pool(pool) {}

    BlockConnector(const BlockConnector&) = delete;
    BlockConnector& operator=(const BlockConnector&) = delete;

    /// Optional UTXO view. When set, each best-chain tip change applies (or, on
    /// a reorg, un-applies) blocks against this view and then runs the Phase-4
    /// stale-input sweep. Left null the UTXO leg is inert -- Phases 1-3
    /// (txid/spent-outpoint based) still run fully, so cold-start/headers-only
    /// is safe.
    void set_utxo(core::coin::UTXOViewCache* u) { m_utxo = u; }

    /// Optional re-request sink. A reorg deeper than the remembered-block
    /// ring (or a headers-first reorg whose intermediate new-branch blocks
    /// have not been downloaded yet) can no longer reconnect from cache; the
    /// missing new-branch hashes are handed here -- wire it to
    /// BlockDownloadWindow::enqueue() so they are re-getdata'd and the reorg
    /// completes on their re-delivery, instead of stranding the UTXO view at
    /// the fork. Left unset the connector falls back to the warn-and-hold
    /// behaviour (UTXO safely parked at the fork until an external resync).
    void set_block_requester(std::function<void(const std::vector<uint256>&)> req) {
        m_request_blocks = std::move(req);
    }

    /// Wire to a node's full_block event. Retained internally, torn down on
    /// destruction (or detach()). Call once, after node + chain + pool exist.
    void attach(bch::interfaces::Node& node) {
        m_sub = node.full_block.subscribe(
            [this](const BlockType& block) { on_full_block(block); });
    }

    /// Drop the subscription early (idempotent). Destruction does this anyway.
    void detach() {
        if (m_sub) {
            m_sub->dispose();
            m_sub.reset();
        }
    }

    /// Connect one received full block. Public so the out-of-tree harness can
    /// drive it without a live Event/socket; in production it is invoked only
    /// by the full_block subscription.
    void on_full_block(const BlockType& block) {
        const uint256 hash =
            block_hash(static_cast<const BlockHeaderType&>(block));

        // 0. Remember the block for a possible forward re-walk on reorg.
        remember_block(hash, block);

        // 1. Block-connect: index the header if new (idempotent on the common
        //    headers-first path where it is already synced).
        m_chain.add_header(static_cast<const BlockHeaderType&>(block));

        // 2. BIP130 best-chain gate: act ONLY when this block is the tip.
        const auto tip = m_chain.tip();
        if (!tip || tip->block_hash != hash) {
            LOG_DEBUG_COIND << "[EMB-BCH] block-connect: " << hash.GetHex().substr(0, 16)
                            << "... not best tip -- state untouched (side/stale/unconnected)";
            return;
        }

        // 3. UTXO sync (forward extend / re-delivery no-op / reorg). Inert when
        //    no view is wired (cold-start / headers-only contract held).
        if (m_utxo)
            sync_utxo_to_tip(*tip);

        // 4. Mempool reconciliation to the new tip.
        m_pool.set_tip_height(tip->height);
        m_pool.remove_for_block(block);          // Phase 1 + 2 + 3 (txid/outpoint)
        int evicted = 0;
        if (m_utxo)
            evicted = m_pool.revalidate_inputs(m_utxo);  // Phase 4: real sweep

        LOG_DEBUG_COIND << "[EMB-BCH] block-connect: tip=" << hash.GetHex().substr(0, 16)
                        << "... height=" << tip->height
                        << " mempool reconciled (size=" << m_pool.size()
                        << " phase4_evicted=" << evicted
                        << " undo_depth=" << m_undo_stack.size() << ")";
    }

    bool is_attached() const { return static_cast<bool>(m_sub); }

    /// True once a re-request sink has been wired (set_block_requester). When
    /// false a deep reorg falls back to warn-and-hold at the fork; when true the
    /// missing new-branch bodies are re-getdata'd. Exposed so the daemon-assembly
    /// path can verify the wiring without a live reorg.
    bool has_block_requester() const { return static_cast<bool>(m_request_blocks); }

    /// Ingest a BIP152 compact block. Reconstructs the full block from the
    /// prefilled txs + the mempool (BCH: short IDs keyed on txid == wtxid). On a
    /// complete reconstruction the block is driven straight through the normal
    /// on_full_block() path and std::nullopt is returned. When txs are missing
    /// the compact block is parked and a getblocktxn request (the missing
    /// absolute indexes) is returned for the caller to send to the announcing
    /// peer; on_block_txn() later closes it out. Idempotent re-announce of an
    /// already-reconstructable block just re-drives the (idempotent) connect.
    std::optional<BlockTransactionsRequest> on_compact_block(const CompactBlock& cb) {
        const uint256 hash = block_hash(cb.header);
        const auto known = m_pool.all_txs_map_wtxid();  // BCH: aliases all_txs_map (txid)
        auto rec = ReconstructBlock(cb, known);
        if (rec.complete) {
            m_pending.erase(hash);          // supersede any earlier partial of this block
            on_full_block(rec.block);
            return std::nullopt;
        }
        m_pending[hash] = cb;               // park: the blocktxn round will finish it
        BlockTransactionsRequest req;
        req.blockhash = hash;
        req.indexes   = rec.missing_indexes;
        LOG_DEBUG_COIND << "[EMB-BCH] compact-block: " << hash.GetHex().substr(0, 16)
                        << "... incomplete -- getblocktxn for " << req.indexes.size()
                        << " tx(s) (pending=" << m_pending.size() << ")";
        return req;
    }

    /// Close out a parked compact block with a blocktxn response. The response
    /// txs (in the order they were requested) are folded into the known-tx set
    /// and the SAME ReconstructBlock pass finishes the block, which is then
    /// driven through on_full_block(). Returns true iff a block was connected.
    /// A response for an unknown/expired blockhash, or one that still leaves the
    /// block short, is a logged no-op (await re-announce) -- never a half-block.
    bool on_block_txn(const BlockTransactionsResponse& resp) {
        auto it = m_pending.find(resp.blockhash);
        if (it == m_pending.end()) {
            LOG_DEBUG_COIND << "[EMB-BCH] blocktxn: no parked compact block for "
                            << resp.blockhash.GetHex().substr(0, 16) << "... -- dropped";
            return false;
        }
        const CompactBlock cb = it->second;
        auto known = m_pool.all_txs_map_wtxid();
        for (const auto& tx : resp.txs)
            known.emplace(compute_txid(tx), tx);   // missing tx not in mempool -> inserts
        auto rec = ReconstructBlock(cb, known);
        m_pending.erase(it);
        if (!rec.complete) {
            LOG_WARNING << "[EMB-BCH] blocktxn for " << resp.blockhash.GetHex().substr(0, 16)
                        << "... left " << rec.missing_indexes.size()
                        << " tx(s) missing (wrong/short set) -- awaiting re-announce";
            return false;
        }
        on_full_block(rec.block);
        return true;
    }

    /// Number of compact blocks parked awaiting a blocktxn round. Diagnostic.
    size_t pending_compact_count() const { return m_pending.size(); }

    /// Depth of retained block-undo (number of best-chain blocks we can roll
    /// back). Diagnostic / test accessor.
    size_t undo_depth() const { return m_undo_stack.size(); }

    ~BlockConnector() { detach(); }

private:
    struct ConnectedEntry {
        uint256                hash;    // block hash (best-chain tip when applied)
        uint256                prev;    // header.m_previous_block
        uint32_t               height;
        BlockType              block;   // retained for disconnect_block() input restore
        core::coin::BlockUndo  undo;    // from connect_block()
    };

    static constexpr size_t kSeenCap = 64;  // remembered-block ring bound

    static uint256 txid_of(const MutableTransaction& tx) { return compute_txid(tx); }

    // ----- remembered-block ring (bounded) ---------------------------------
    void remember_block(const uint256& h, const BlockType& b) {
        if (m_seen.find(h) != m_seen.end()) return;
        m_seen.emplace(h, b);
        m_seen_order.push_back(h);
        while (m_seen_order.size() > kSeenCap) {
            m_seen.erase(m_seen_order.front());
            m_seen_order.pop_front();
        }
    }
    const BlockType* recall_block(const uint256& h) const {
        auto it = m_seen.find(h);
        return it == m_seen.end() ? nullptr : &it->second;
    }

    // ----- connected-chain bookkeeping -------------------------------------
    /// True if `h` is part of the UTXO-applied chain: the current tip, any
    /// retained undo entry, or the pre-connector base (the parent of the bottom
    /// of the undo stack -- the checkpoint/seed we started syncing from).
    bool is_connected(const uint256& h) const {
        if (h.IsNull()) return false;
        if (h == m_connected_tip) return true;
        for (const auto& e : m_undo_stack)
            if (e.hash == h) return true;
        if (!m_undo_stack.empty() && h == m_undo_stack.front().prev)
            return true;  // fork at the base we began from
        return false;
    }

    void connect_one(const uint256& hash, const BlockType& block, uint32_t height) {
        core::coin::BlockUndo undo =
            m_utxo->connect_block(block, height, &BlockConnector::txid_of);
        m_undo_stack.push_back(
            ConnectedEntry{hash, block.m_previous_block, height, block, std::move(undo)});
        m_connected_tip = hash;
    }

    void disconnect_one() {
        ConnectedEntry e = std::move(m_undo_stack.back());
        m_undo_stack.pop_back();
        m_utxo->disconnect_block(e.block, e.undo, &BlockConnector::txid_of);
        // Return the disconnected block's non-coinbase txs to the mempool: they
        // are no longer confirmed on our best chain. add_tx de-dupes and
        // re-derives fee against the now-rolled-back view.
        for (size_t i = 1; i < e.block.m_txs.size(); ++i)
            m_pool.add_tx(e.block.m_txs[i], m_utxo);
        m_connected_tip = e.prev;
        LOG_DEBUG_COIND << "[EMB-BCH] reorg: disconnected " << e.hash.GetHex().substr(0, 16)
                        << "... height=" << e.height
                        << " (restored " << (e.block.m_txs.empty() ? 0 : e.block.m_txs.size() - 1)
                        << " tx to mempool)";
    }

    /// Bring the UTXO view from m_connected_tip to `tip`: forward extend, an
    /// idempotent re-delivery no-op, or a full reorg (disconnect old branch to
    /// the fork point, reconnect the new branch from the remembered-block ring).
    void sync_utxo_to_tip(const IndexEntry& tip) {
        const uint256  new_tip  = tip.block_hash;
        const uint256& new_prev = tip.header.m_previous_block;

        if (new_tip == m_connected_tip)
            return;  // re-delivery of the current tip: nothing to apply.

        if (m_connected_tip.IsNull() || new_prev == m_connected_tip) {
            const BlockType* blk = recall_block(new_tip);
            if (blk) connect_one(new_tip, *blk, tip.height);
            return;  // forward extend (covers the first connect: cold start).
        }

        // REORG. Build the new-branch path from the new tip back to the first
        // ancestor that is already on our connected chain (the fork point).
        std::vector<uint256> connect_path;   // new tip ... first-above-fork (reverse order)
        uint256 cursor = new_tip;
        while (!is_connected(cursor)) {
            connect_path.push_back(cursor);
            auto e = m_chain.get_header(cursor);
            if (!e || e->header.m_previous_block.IsNull()) break;
            cursor = e->header.m_previous_block;
        }
        const uint256 fork = cursor;

        // Disconnect everything above the fork point (deepest-first via pop).
        while (!m_undo_stack.empty() && m_undo_stack.back().hash != fork)
            disconnect_one();

        // Reconnect the new branch fork -> new tip from the remembered ring.
        for (auto it = connect_path.rbegin(); it != connect_path.rend(); ++it) {
            const BlockType* blk = recall_block(*it);
            if (!blk) {
                // Reorg deeper than the remembered ring (or a headers-first
                // reorg whose intermediate new-branch blocks were not yet
                // downloaded): this block and every block still above it on
                // the path are absent from the cache. Re-request them for
                // getdata so the reorg completes on their re-delivery instead
                // of stranding the UTXO at the fork. The sink (enqueue())
                // dedupes, so an overlapping request never double-getdata's.
                // `it .. rend()` is exactly the not-yet-connected tail, in
                // fork->tip connect order.
                std::vector<uint256> missing(it, connect_path.rend());
                LOG_WARNING << "[EMB-BCH] reorg: new-branch block "
                                  << it->GetHex().substr(0, 16)
                                  << "... not retained -- re-requesting " << missing.size()
                                  << " block(s), UTXO held at fork until re-delivery";
                if (m_request_blocks)
                    m_request_blocks(missing);
                return;
            }
            auto e = m_chain.get_header(*it);
            connect_one(*it, *blk, e ? e->height : 0);
        }
    }

    HeaderChain&                 m_chain;
    Mempool&                     m_pool;
    core::coin::UTXOViewCache*   m_utxo {nullptr};   // optional UTXO view
    // Re-request sink for reorg blocks absent from the remembered ring
    // (see set_block_requester). Unset -> warn-and-hold at the fork.
    std::function<void(const std::vector<uint256>&)> m_request_blocks;

    uint256                      m_connected_tip {}; // null = nothing applied yet
    std::vector<ConnectedEntry>  m_undo_stack;       // applied best-chain blocks
    std::unordered_map<uint256, BlockType, Uint256Hasher> m_seen;  // remembered ring
    std::deque<uint256>          m_seen_order;        // ring eviction order
    // Compact blocks awaiting a getblocktxn/blocktxn round (keyed by block hash).
    std::unordered_map<uint256, CompactBlock, Uint256Hasher> m_pending;

    std::shared_ptr<EventDisposable> m_sub;
};

} // namespace coin
} // namespace bch