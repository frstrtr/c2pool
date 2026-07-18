// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

/// Phase U capstone (E2b, #738): the LIVE Dash UTXO/fee lane.
///
/// utxo_adapter.hpp shipped the type-compatibility shim (DASH_LIMITS /
/// DASH_MIN_BLOCKS_TO_KEEP / DASH_MINING_GATE_DEPTH / dash_txid) with the
/// explicit note "no live UTXOViewCache instance is constructed yet". That
/// gap is the root cause of the #738 differential's fee_known=false ->
/// empty-template defect: Mempool::set_utxo had ZERO callers in the dash
/// arm, so m_utxo stayed nullptr, every entry stayed fee_known=false, and
/// the conservative selection guard (unknown-fee txs EXCLUDED so
/// coinbasevalue can never overstate vs dashd's GBT) correctly returned an
/// empty selection forever.
///
/// This header is a TRANSLITERATION of the PROVEN, LIVE Litecoin wiring in
/// src/c2pool/main_ltc.cpp:
///   - UTXOViewDB + UTXOViewCache construction with open-retry
///     (main_ltc.cpp ~1750-1780) -> UtxoLane::open()
///   - pool->set_utxo(cache)              (~1770)  -> UtxoLane::attach()
///   - coinbase-maturity mining gate      (~1785-1801) -> mining_utxo_ready()
///   - block-connect leg: connect_block + put_block_undo + flush +
///     prune_undo + mempool remove_for_block + recompute_unknown_fees
///     (~2385-2433) -> on_block_connected() / connect_one()
///   - cold-start ordered-download pipeline over the N-block window
///     (core/coin/block_bootstrapper.hpp, main_ltc.cpp ~2160-2379)
///     -> the BlockBootstrapState<BlockType> branch, window = 288
///        (DASH_MIN_BLOCKS_TO_KEEP, dashcore validation.h MIN_BLOCKS_TO_KEEP)
///
/// Differences from the LTC reference (each deliberate, none behavioral):
///   - Dash's block_connected seam (node_interface.hpp BlockConnected)
///     already pairs (block, height), so the header-chain height lookup the
///     LTC handler performs is unnecessary; the block hash is recomputed
///     here (X11(header) = Dash block identity, header_chain.hpp).
///   - No MWEB tracker / HogEx handling (Dash has no MWEB; the shared
///     connect_block template sees MutableTransaction::m_hogEx == false).
///   - The LIVE block feed + full-block request plumbing is E1/E2a's leg
///     (the coin P2P transport). This lane exposes exactly two seams for
///     it: on_block_connected() (subscribe to Node::block_connected) and
///     set_request_block_fn() (bootstrap window refill / stall re-request,
///     the analog of broadcaster->request_full_block by height). Until E2a
///     connects them the lane is dormant and byte-inert.
///
/// FENCED: src/impl/dash only. Constructed exclusively by the opt-in
/// embedded path in main_dash.cpp; the dashd-RPC fallback (mining-hotel
/// prod) never touches this file.

#include "block.hpp"
#include "mempool.hpp"
#include "utxo_adapter.hpp"

#include <impl/dash/crypto/hash_x11.hpp>

#include <core/coin/block_bootstrapper.hpp>
#include <core/leveldb_store.hpp>
#include <core/log.hpp>
#include <core/pack.hpp>
#include <core/uint256.hpp>

#include <chrono>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <thread>
#include <utility>

namespace dash {
namespace coin {

class UtxoLane {
public:
    /// Bootstrap window-refill / stall re-request seam. E1/E2a wires this to
    /// the coin P2P transport's request-full-block-by-height path (the analog
    /// of the LTC broadcaster->request_full_block(header_by_height(h).hash)).
    using RequestBlockFn = std::function<void(uint32_t height)>;

    UtxoLane() = default;
    UtxoLane(const UtxoLane&) = delete;
    UtxoLane& operator=(const UtxoLane&) = delete;

    /// Open the LevelDB-backed UTXO store and build the write-back cache.
    /// Mirrors main_ltc.cpp ~1750-1780: 32 MB block cache / 8 MB write
    /// buffer, 5 open attempts 2 s apart. Returns live() on success.
    ///
    /// An EMPTY db_path builds an ephemeral cache-only view (no LevelDB
    /// base) — the synthetic-block KAT mode; persistence calls are skipped.
    bool open(const std::string& db_path)
    {
        if (db_path.empty()) {
            m_cache = std::make_unique<UtxoViewCache>(nullptr);
            LOG_INFO << "[EMB-DASH] UTXO lane: ephemeral (no LevelDB base)";
            return true;
        }
        ::core::LevelDBOptions utxo_opts;
        utxo_opts.block_cache_size  = 32 * 1024 * 1024;  // 32 MB cache
        utxo_opts.write_buffer_size =  8 * 1024 * 1024;  // 8 MB
        bool utxo_ok = false;
        for (int attempt = 1; attempt <= 5; ++attempt) {
            m_db = std::make_unique<UtxoViewDB>(db_path, utxo_opts);
            if (m_db->open()) { utxo_ok = true; break; }
            LOG_WARNING << "[EMB-DASH] UTXO DB open failed (attempt "
                        << attempt << "/5) — retrying in 2s...";
            std::this_thread::sleep_for(std::chrono::seconds(2));
        }
        if (!utxo_ok) {
            LOG_WARNING << "[EMB-DASH] UTXO DB failed to open after 5 attempts"
                           " — fees will be unknown";
            m_db.reset();
            return false;
        }
        m_cache = std::make_unique<UtxoViewCache>(m_db.get());
        LOG_INFO << "[EMB-DASH] UTXO set opened: best_height="
                 << m_db->get_best_height() << " best_block="
                 << m_db->get_best_block().GetHex().substr(0, 16);
        return true;
    }

    bool live() const { return static_cast<bool>(m_cache); }
    UtxoViewCache* cache() { return m_cache.get(); }
    UtxoViewDB*    db()    { return m_db.get(); }

    /// The set_utxo call the dash arm never made (main_ltc.cpp:1770).
    /// After this, Mempool::add_tx prices via UTXO+CPFP and
    /// recompute_unknown_fees can resolve backlog entries.
    void attach(Mempool& pool)
    {
        m_pool = &pool;
        if (m_cache) pool.set_utxo(m_cache.get());
    }

    void set_request_block_fn(RequestBlockFn fn) { m_request_fn = std::move(fn); }

    /// Coinbase-maturity mining gate (main_ltc.cpp ~1785-1801): embedded
    /// templates must not be built until the UTXO view is at least
    /// coinbase_maturity + reorg-buffer deep, or they may spend immature
    /// coinbase outputs. DASH_MINING_GATE_DEPTH = 100 + 6 = 106
    /// (utxo_adapter.hpp; dashcore consensus.h COINBASE_MATURITY).
    bool mining_utxo_ready() const
    {
        if (!m_cache) return false;
        const auto connected = m_cache->blocks_connected();
        const bool ready = connected >= DASH_MINING_GATE_DEPTH;
        if (!ready) {
            static int s_log_ctr = 0;
            if (s_log_ctr++ % 20 == 0)
                LOG_INFO << "[EMB-DASH] UTXO maturity gate: blocks_connected="
                         << connected << " need>=" << DASH_MINING_GATE_DEPTH;
        }
        return ready;
    }

    /// The E2a seam — subscribe to dash::interfaces::Node::block_connected
    /// (the leg-3 event of block_connect_ingest.hpp; it pairs block+height,
    /// so no header-chain lookup is needed here). Transliterates the LTC
    /// full-block handler (main_ltc.cpp ~2199-2433): bootstrap trigger ->
    /// ordered drain -> window refill, else normal single-block connect;
    /// mempool cleanup + fee recompute in both modes.
    void on_block_connected(const BlockType& block, uint32_t height)
    {
        if (!m_cache) return;

        // Dash block identity = X11(header) (header_chain.hpp).
        auto packed_hdr = ::pack(
            static_cast<const ::dash::coin::BlockHeaderType&>(block));
        const uint256 block_hash =
            ::dash::crypto::hash_x11(packed_hdr.get_span());

        constexpr uint32_t DASH_KEEP = DASH_MIN_BLOCKS_TO_KEEP;  // 288

        // ═══ BOOTSTRAP PIPELINE (cold start) ══════════════════════════════
        // 1. Trigger — fires BEFORE connecting the first block so
        //    best_height isn't set prematurely (else every bootstrap block
        //    below the tip silently fails the height > best_height guard).
        if (!m_bootstrap_done && !m_bs.active && height > DASH_KEEP) {
            m_bootstrap_done = true;
            const uint32_t utxo_best = m_cache->get_best_height();
            const uint32_t start_from =
                (utxo_best > 0 && utxo_best >= height - DASH_KEEP)
                ? utxo_best + 1 : height - DASH_KEEP;

            if (start_from < height) {
                m_bs.active       = true;
                m_bs.next_height  = start_from;
                m_bs.end_height   = height;
                m_bs.next_request = start_from;
                m_bs.total        = height - start_from + 1;
                m_bs.buffer[height] = {block, block_hash};
                m_bs.last_drain_time = std::chrono::steady_clock::now();

                int requested = 0;
                while (m_bs.next_request <= m_bs.end_height &&
                       (m_bs.next_request - m_bs.next_height)
                           < m_bs.WINDOW_SIZE) {
                    if (!m_bs.buffer.count(m_bs.next_request)) {
                        request_block(m_bs.next_request);
                        ++requested;
                    }
                    ++m_bs.next_request;
                }
                LOG_INFO << "[EMB-DASH] Bootstrap pipeline: " << m_bs.total
                         << " blocks [" << start_from << ".." << height << "]"
                         << " window=" << m_bs.WINDOW_SIZE
                         << " requests=" << requested;
                return;
            }
            LOG_INFO << "[EMB-DASH] UTXO warm restart: best=" << utxo_best
                     << " — no bootstrap needed";
        }

        // 2. Bootstrap active: buffer -> drain in height order -> refill.
        if (m_bs.active) {
            if (height >= m_bs.next_height && height <= m_bs.end_height) {
                m_bs.buffer.try_emplace(height,
                                        std::make_pair(block, block_hash));
            } else if (height > m_bs.end_height) {
                // New block mined during bootstrap — extend range.
                m_bs.end_height = height;
                m_bs.total = m_bs.processed
                    + (m_bs.end_height - m_bs.next_height + 1);
                m_bs.buffer.try_emplace(height,
                                        std::make_pair(block, block_hash));
            }

            // Stall detection: re-request the missing block if stuck.
            const auto now = std::chrono::steady_clock::now();
            const auto stall = std::chrono::duration_cast<std::chrono::seconds>(
                now - m_bs.last_drain_time).count();
            if (stall >= m_bs.STALL_TIMEOUT_SEC) {
                LOG_WARNING << "[EMB-DASH] Bootstrap stall h="
                            << m_bs.next_height << " (" << stall
                            << "s) — re-request fallback";
                request_block(m_bs.next_height);
                m_bs.last_drain_time = now;
            }

            // Drain consecutive blocks in height order.
            bool drained_any = false;
            while (m_bs.buffer.count(m_bs.next_height)) {
                auto node = m_bs.buffer.extract(m_bs.next_height);
                auto& [b, bh] = node.mapped();
                connect_one(b, m_bs.next_height, bh);
                drained_any = true;
                ++m_bs.next_height;
                ++m_bs.processed;
                m_bs.last_drain_time = std::chrono::steady_clock::now();
            }

            static int bs_log = 0;
            if (++bs_log % 20 == 0 || m_bs.next_height > m_bs.end_height) {
                LOG_INFO << "[EMB-DASH] Bootstrap: " << m_bs.processed << "/"
                         << m_bs.total << " buf=" << m_bs.buffer.size();
            }

            // Refill sliding window.
            while (m_bs.next_request <= m_bs.end_height
                   && (m_bs.next_request - m_bs.next_height)
                       < m_bs.WINDOW_SIZE) {
                if (!m_bs.buffer.count(m_bs.next_request))
                    request_block(m_bs.next_request);
                ++m_bs.next_request;
            }

            if (m_bs.next_height > m_bs.end_height) {
                m_bs.active = false;
                m_bs.stop_stall_timer();
                LOG_INFO << "[EMB-DASH] Bootstrap complete: "
                         << m_bs.processed << " blocks";
            }

            if (drained_any) recompute_fees();
            return;
        }

        // 3. Normal processing (after bootstrap or warm restart) —
        //    main_ltc.cpp ~2385-2433.
        if (height > m_cache->get_best_height()) {
            connect_one(block, height, block_hash);

            static int utxo_log = 0;
            if (utxo_log++ % 10 == 0) {
                LOG_INFO << "[EMB-DASH] UTXO: block " << height << " hash="
                         << block_hash.GetHex().substr(0, 16)
                         << " txs=" << block.m_txs.size()
                         << " cache=" << m_cache->cache_size();
            }
        } else if (m_pool) {
            // UTXO already past this height (duplicate / raced delivery):
            // still clear confirmed txs from the mempool, as the LTC handler
            // does outside its height guard.
            m_pool->remove_for_block(block);
        }
        recompute_fees();
    }

private:
    /// Single-block connect: UTXO spend/add + undo persist + flush + prune
    /// + mempool confirm-eviction. Mirrors the per-block body of both the
    /// LTC drain loop (~2303-2311) and normal leg (~2387-2391).
    void connect_one(const BlockType& block, uint32_t height,
                     const uint256& block_hash)
    {
        auto undo = m_cache->connect_block(
            block, height,
            [](const MutableTransaction& tx) { return dash_txid(tx); });
        if (m_db) m_db->put_block_undo(height, undo);
        m_cache->flush(block_hash, height);
        m_cache->prune_undo(height, DASH_MIN_BLOCKS_TO_KEEP);
        if (m_pool) m_pool->remove_for_block(block);
    }

    /// Post-connect fee revalidation (main_ltc.cpp:2428): the block's
    /// outputs are now in UTXO and may resolve previously-unknown inputs,
    /// flipping entries fee_known and into the feerate-sorted selection.
    void recompute_fees()
    {
        if (m_pool && m_cache)
            m_pool->recompute_unknown_fees(m_cache.get());
    }

    void request_block(uint32_t height)
    {
        if (m_request_fn) { m_request_fn(height); return; }
        static bool warned = false;
        if (!warned) {
            warned = true;
            LOG_WARNING << "[EMB-DASH] UTXO bootstrap wants block h=" << height
                        << " but no request seam is wired"
                           " (set_request_block_fn — the E1/E2a live-feed leg);"
                           " relying on inbound delivery only";
        }
    }

    std::unique_ptr<UtxoViewDB>    m_db;
    std::unique_ptr<UtxoViewCache> m_cache;
    Mempool*                       m_pool{nullptr};
    RequestBlockFn                 m_request_fn;
    ::core::coin::BlockBootstrapState<BlockType> m_bs;
    bool                           m_bootstrap_done{false};
};

} // namespace coin
} // namespace dash
