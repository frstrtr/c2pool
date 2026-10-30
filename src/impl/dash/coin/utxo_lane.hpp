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
/// FULL MODE (DESIGN S2 4.3, the DASH full UTXO set from a pinned snapshot).
/// open_full() takes <net>/utxo_full_leveldb, opened under the S2-2 rule by
/// utxo_snapshot_import.hpp. The set holds every coin of the chain up to its
/// best block, so the lane never jumps (no height-288 restart) and connects
/// strictly:
///   - verify_base(): the assumed base must be the header chain's block at its
///     height before the set connects or prices anything at the tip;
///   - every block is the header chain's block at its height and links to the
///     set's best; a fork body is dropped (bad_bodies), never connected;
///   - best+1 .. the header tip is filled in order (FULL_WINDOW requests in
///     flight, one per height, stall re-ask as in the bootstrap), from the
///     first block_connected or from on_header_tip();
///   - connect = BIP30 (an output whose outpoint is already a coin refuses)
///     and an output with value 0 and an empty script refuses
///     (Coin::is_spent() reads such a coin as absent, VERIFY-S1 S2-3), then
///     UTXOViewCache::connect_block(strict): every input a coin of the set or
///     of an earlier tx of the block, each spent once. Special txs need no
///     rule of their own: QcTx/MnHfTx have no inputs and no outputs, an
///     AssetUnlock has no inputs and adds its outputs, an AssetLock's
///     OP_RETURN is unspendable and skipped, a CbTx is the coinbase;
///   - a refusal asks the body again once; a second refusal at the same
///     height means the SET is wrong: the lane WITHHOLDS (stops advancing,
///     utxo_current_at() false so templates carry no mempool tx, an alert, a
///     named reason in the status), and never heals by jumping or wiping;
///   - a best block that left the header chain's best is disconnected from
///     its undo record (rewind), back to the base at most; deeper withholds.
///
/// FENCED: src/impl/dash only. Constructed exclusively by the opt-in
/// embedded path in main_dash.cpp; the dashd-RPC fallback (production
/// prod) never touches this file.

#include "block.hpp"
#include "mempool.hpp"
#include "utxo_adapter.hpp"

#include <impl/dash/crypto/hash_x11.hpp>

#include <core/coin/block_bootstrapper.hpp>
#include <core/coin/utxo_assumed.hpp>
#include <core/leveldb_store.hpp>
#include <core/log.hpp>
#include <core/pack.hpp>
#include <core/uint256.hpp>

#include <boost/asio/io_context.hpp>
#include <boost/asio/steady_timer.hpp>

#include <chrono>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <thread>
#include <utility>
#include <vector>

namespace dash {
namespace coin {

class UtxoLane {
public:
    /// Bootstrap window-refill / stall re-request seam. E1/E2a wires this to
    /// the coin P2P transport's request-full-block-by-height path (the analog
    /// of the LTC broadcaster->request_full_block(header_by_height(h).hash)).
    ///
    /// Returns the truth of the wire, the MnCheckpointLane #138 contract:
    /// FALSE when the request died locally (the header for h is not held
    /// yet, or no peer route exists), so the lane keeps the height on its
    /// dead-send list and re-asks it, instead of treating it as in flight.
    using RequestBlockFn = std::function<bool(uint32_t height)>;
    using Clock = std::chrono::steady_clock;
    using BootstrapState = ::core::coin::BlockBootstrapState<BlockType>;

    enum class Mode : uint8_t { Accrual, Full };
    /// The header chain's block hash at a height (nullopt = not held).
    using HashAtFn = std::function<std::optional<uint256>(uint32_t height)>;
    /// A withhold, for the alert relay: (event, detail).
    using AlertFn = std::function<void(const std::string& event, const std::string& detail)>;

    /// Requests in flight while a full set fills best+1 .. tip (the DOGE
    /// branch's ordered-fill window, DESIGN 4.3).
    static constexpr size_t FULL_WINDOW = 64;

    /// What a full set is doing, for /local_stats and [EMBED-STATUS].
    struct FullStatus {
        bool        full{false};
        std::string state;           // verifying-base | catching-up | serving | withheld
        uint32_t    best_height{0};
        uint256     best_block;
        uint64_t    coins{0};
        uint32_t    base_height{0};
        uint256     base_hash;
        uint256     muhash;
        bool        base_verified{false};
        bool        validated{false};
        uint64_t    connected{0};
        uint64_t    strict_refusals{0};
        uint64_t    bad_bodies{0};
        uint64_t    rewinds{0};
        uint32_t    fill_next{0};
        uint32_t    fill_end{0};
        std::string withheld_reason;
    };

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

    /// Full mode: take the full set opened by open_dash_full_utxo_set (the
    /// S2-2 rule already held). Nothing is connected or priced at the tip
    /// until verify_base() places the assumed base on the header chain.
    bool open_full(std::unique_ptr<UtxoViewDB> db, const ::core::coin::AssumedBase& assumed,
                   uint32_t min_base_height)
    {
        if (!db) return false;
        m_db = std::move(db);
        m_cache = std::make_unique<UtxoViewCache>(m_db.get());
        m_mode = Mode::Full;
        m_assumed = assumed;
        m_min_base_height = min_base_height;
        m_bs.window = FULL_WINDOW;
        m_bs.phase = "Catch-up";
        LOG_INFO << "[EMB-DASH] UTXO set: FULL, best=" << m_db->get_best_height()
                 << " best_block=" << m_db->get_best_block().GetHex().substr(0, 16)
                 << " assumed_base=" << assumed.base_height
                 << " validated=" << int(assumed.validated)
                 << " coins=" << m_db->get_sync_state().coins;
        return true;
    }

    bool live() const { return static_cast<bool>(m_cache); }
    UtxoViewCache* cache() { return m_cache.get(); }
    UtxoViewDB*    db()    { return m_db.get(); }

    Mode mode() const { return m_mode; }
    bool full() const { return m_mode == Mode::Full; }
    bool withheld() const { return m_withheld; }
    bool base_verified() const { return m_base_verified; }
    void set_hash_at_fn(HashAtFn fn) { m_hash_at = std::move(fn); }
    void set_alert_fn(AlertFn fn) { m_alert = std::move(fn); }

    FullStatus full_status() const
    {
        FullStatus st;
        st.full = m_mode == Mode::Full;
        if (!st.full || !m_cache) return st;
        st.best_height = m_cache->get_best_height();
        st.best_block = m_cache->get_best_block();
        st.coins = m_cache->sync_state().coins;
        st.base_height = m_assumed.base_height;
        st.base_hash = m_assumed.base_hash;
        st.muhash = m_assumed.muhash;
        st.base_verified = m_base_verified;
        st.validated = m_assumed.validated != 0;
        st.connected = m_full_connected;
        st.strict_refusals = m_strict_refusals;
        st.bad_bodies = m_bad_bodies;
        st.rewinds = m_rewinds;
        st.fill_next = m_bs.active ? m_bs.next_height : 0;
        st.fill_end = m_bs.active ? m_bs.end_height : 0;
        st.withheld_reason = m_withheld_reason;
        if (m_withheld)            st.state = "withheld";
        else if (!m_base_verified) st.state = "verifying-base";
        else if (m_bs.active)      st.state = "catching-up";
        else                       st.state = "serving";
        return st;
    }

    /// Full mode: the header tip moved. Places the base, rewinds a best block
    /// that left the best chain, and asks for best+1 .. tip without waiting
    /// for a block to be announced. No-op in accrual mode.
    void on_header_tip(uint32_t tip_height)
    {
        if (m_mode != Mode::Full || !m_cache || m_withheld) return;
        if (!verify_base() || !rewind_to_best_chain()) return;
        const uint32_t best_h = m_cache->get_best_height();
        if (tip_height <= best_h && !m_bs.active) return;
        start_fill(best_h);
        if (tip_height > m_bs.end_height) m_bs.end_height = tip_height;
        fill_step();
    }

    /// The set_utxo call the dash arm never made (main_ltc.cpp:1770).
    /// After this, Mempool::add_tx prices via UTXO+CPFP and
    /// recompute_unknown_fees can resolve backlog entries.
    void attach(Mempool& pool)
    {
        m_pool = &pool;
        if (m_cache) pool.set_utxo(m_cache.get());
    }

    void set_request_block_fn(RequestBlockFn fn) { m_request_fn = std::move(fn); }

    /// Test seam: the bootstrap stall clock. Defaults to steady_clock.
    void set_clock_fn(std::function<Clock::time_point()> fn) { m_now_fn = std::move(fn); }

    /// Arm the bootstrap watchdog timer (the main_ltc.cpp:2444 /
    /// main_ltc.cpp:6031 start_stall_timer analog the DASH arm never had).
    /// The timer runs only while a bootstrap is active: it starts when the
    /// bootstrap triggers and stops when it completes. Each tick runs
    /// service_bootstrap(), so recovery no longer waits for the next live
    /// block. Must be the io_context thread that delivers block_connected.
    void arm_stall_timer(boost::asio::io_context& ioc,
                         std::chrono::milliseconds interval =
                             std::chrono::seconds(BootstrapState::STALL_CHECK_SEC))
    {
        m_stall_timer = std::make_unique<boost::asio::steady_timer>(ioc);
        m_stall_interval = interval;
        schedule_stall_tick();
    }

    /// Bootstrap watchdog, run from every block_connected event and every
    /// stall-timer tick:
    ///   1. re-ask every DEAD SEND (a request the seam reported as not put
    ///      on the wire). On a fresh node the bootstrap fires on the first
    ///      bridge block, before the pre-anchor header backfill installs, so
    ///      the whole first window dies on the missing header lookup.
    ///   2. on a STALL_TIMEOUT_SEC stall, re-ask the WHOLE outstanding window
    ///      (every unbuffered height in [next_height, next_request)), not
    ///      only next_height. Re-asking one height per stall recovered a
    ///      16-block dead window one live block at a time (~55 min).
    void service_bootstrap()
    {
        if (!m_bs.active) return;

        retry_dead_sends();

        const auto now = now_();
        const auto stall = std::chrono::duration_cast<std::chrono::seconds>(
            now - m_bs.last_drain_time).count();
        if (stall >= m_bs.STALL_TIMEOUT_SEC) {
            int reasked = 0;
            for (uint32_t h = m_bs.next_height; h < m_bs.next_request; ++h)
                if (!m_bs.buffer.count(h) && request_block(h)) ++reasked;
            LOG_WARNING << "[EMB-DASH] Bootstrap stall h=" << m_bs.next_height
                        << " (" << stall << "s) — re-requested " << reasked
                        << " outstanding window block(s)";
            m_bs.last_drain_time = now;
        }
    }

    /// Heights whose request died locally and are waiting to be re-asked.
    size_t dead_sends() const { return m_dead_sends.size(); }

    /// Coinbase-maturity mining gate (main_ltc.cpp ~1785-1801): embedded
    /// templates must not INCLUDE MEMPOOL TXS until the UTXO view is at least
    /// coinbase_maturity + reorg-buffer deep, or they may spend immature
    /// coinbase outputs / misprice a fee. DASH_MINING_GATE_DEPTH = 100 + 6 = 106
    /// (utxo_adapter.hpp; dashcore consensus.h COINBASE_MATURITY).
    ///
    /// This predicate reports only the DEPTH. What the arm does while it is
    /// false is NodeCoinState::set_utxo_immature_policy's decision: the DEFAULT
    /// refuses the whole window (p2pool semantics -- an unsynced node does not
    /// serve templates; the dashd fallback serves full ones where armed), and
    /// the pure-daemonless opt-in serves a coinbase-only template instead
    /// (consensus requires no mempool tx; with zero txs the fee term is exactly
    /// 0, so nothing can be overstated).
    bool mining_utxo_ready() const
    {
        if (!m_cache) return false;
        // A full set holds every coin up to its best: the depth gate is moot.
        // Ready once its base is on the header chain; whether a template may
        // carry mempool txs is utxo_current_at()'s answer (best == tip, not
        // withheld).
        if (m_mode == Mode::Full) return m_base_verified;
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

    /// WINDOW-2 currency predicate (intra-node eviction lag).
    ///
    /// Reports whether the embedded UTXO view has ALREADY connected the block
    /// identified by `tip_hash` -- i.e. its spends are applied and (because
    /// connect_one calls Mempool::remove_for_block on the same block, same io
    /// thread, before returning) that block's txs + newly-conflicting mempool
    /// txs are evicted. `get_best_block()` is set atomically by the per-block
    /// flush() inside connect_one, so equality is exact.
    ///
    /// The serve tip can be promoted to a height H by a DIFFERENT, earlier
    /// event than the UTXO connect: the diff-driven promotion in
    /// CoinStateMaintainer (mnlistdiff-at-tip / cbTx credit-pool re-anchor)
    /// advances the serve tip with no UTXO/mempool axis among its promotion
    /// conjuncts. In that window the view is still at H-1, H's spent outpoints
    /// still resolve as unspent, and H's txs would pass the selection guard
    /// into an H+1 template -> bad-txns-inputs-missingorspent on a winning
    /// share = a thrown-away found block. dashd cannot expose this window
    /// because CTxMemPool::removeForBlock runs synchronously inside
    /// ConnectBlock BEFORE SetTip. The serve path consults this predicate and
    /// serves coinbase-only (fees=0, exact) until the view catches up -- the
    /// fail-closed equivalent of dashd's atomicity across two async events
    /// (header arrival vs body arrival) that c2pool cannot hold one lock over.
    bool utxo_current_at(const uint256& tip_hash) const
    {
        if (m_mode == Mode::Full && (!m_base_verified || m_withheld)) return false;
        return m_cache && m_cache->get_best_block() == tip_hash;
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

        if (m_mode == Mode::Full) {
            on_block_full(block, height, block_hash);
            return;
        }

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
                m_bs.last_drain_time = now_();

                int requested = 0;
                while (m_bs.next_request <= m_bs.end_height &&
                       (m_bs.next_request - m_bs.next_height)
                           < m_bs.WINDOW_SIZE) {
                    if (!m_bs.buffer.count(m_bs.next_request)
                        && request_block(m_bs.next_request))
                        ++requested;
                    ++m_bs.next_request;
                }
                LOG_INFO << "[EMB-DASH] Bootstrap pipeline: " << m_bs.total
                         << " blocks [" << start_from << ".." << height << "]"
                         << " window=" << m_bs.WINDOW_SIZE
                         << " requests=" << requested
                         << " dead=" << m_dead_sends.size();
                schedule_stall_tick();
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

            // Dead-send retry + stall re-request (also run by the timer).
            service_bootstrap();

            // Drain consecutive blocks in height order.
            bool drained_any = false;
            while (m_bs.buffer.count(m_bs.next_height)) {
                auto node = m_bs.buffer.extract(m_bs.next_height);
                auto& [b, bh] = node.mapped();
                connect_one(b, m_bs.next_height, bh);
                drained_any = true;
                ++m_bs.next_height;
                ++m_bs.processed;
                m_bs.last_drain_time = now_();
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
                m_dead_sends.clear();
                if (m_stall_timer) m_stall_timer->cancel();
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
    // ═══ FULL MODE ═══════════════════════════════════════════════════════

    enum class FullConnect : uint8_t { Connected, Dropped, Refused, Rewound };

    void on_block_full(const BlockType& block, uint32_t height, const uint256& block_hash)
    {
        if (m_withheld || !verify_base() || !rewind_to_best_chain()) {
            if (m_pool) m_pool->remove_for_block(block);
            return;
        }
        const uint32_t best_h = m_cache->get_best_height();
        if (height <= best_h) {
            if (m_pool) m_pool->remove_for_block(block);
            return;
        }
        if (m_hash_at) {
            const auto hh = m_hash_at(height);
            if (hh && *hh != block_hash) {
                ++m_bad_bodies;
                LOG_WARNING << "[EMB-DASH] UTXO full: h=" << height << " body "
                            << block_hash.GetHex().substr(0, 16)
                            << " is not the header chain's block there; dropped";
                return;
            }
        }
        start_fill(best_h);
        if (height > m_bs.end_height) m_bs.end_height = height;
        m_bs.buffer.try_emplace(height, std::make_pair(block, block_hash));
        fill_step();
    }

    /// The assumed base is the header chain's block at its height. Waits
    /// (false) while the header chain is below it; withholds on a mismatch.
    bool verify_base()
    {
        if (m_base_verified) return true;
        if (m_withheld) return false;
        if (m_assumed.base_height < m_min_base_height) {
            withhold("utxo-full-base-below-checkpoint",
                     "base " + std::to_string(m_assumed.base_height) + " < checkpoint " +
                         std::to_string(m_min_base_height));
            return false;
        }
        if (!m_hash_at) return false;
        const auto hh = m_hash_at(m_assumed.base_height);
        if (!hh) return false;
        if (*hh != m_assumed.base_hash) {
            withhold("utxo-full-base-not-in-header-chain",
                     "header at " + std::to_string(m_assumed.base_height) + " is " + hh->GetHex() +
                         ", the set's base is " + m_assumed.base_hash.GetHex());
            return false;
        }
        m_base_verified = true;
        LOG_INFO << "[EMB-DASH] UTXO full set: base h=" << m_assumed.base_height << " "
                 << m_assumed.base_hash.GetHex().substr(0, 16)
                 << " is the header chain's block there; best=" << m_cache->get_best_height();
        return true;
    }

    /// Disconnect, from the undo records, every best block that is no longer
    /// the header chain's block at its height. False = withheld.
    bool rewind_to_best_chain()
    {
        if (!m_hash_at) return true;
        while (true) {
            const uint32_t bh = m_cache->get_best_height();
            const uint256 best = m_cache->get_best_block();
            const auto hh = m_hash_at(bh);
            if (!hh || *hh == best) return true;
            if (bh <= m_assumed.base_height) {
                withhold("utxo-reorg-below-snapshot-base",
                         "best h=" + std::to_string(bh) + " " + best.GetHex() + " left the best chain");
                return false;
            }
            BlockUndo u;
            if (!m_db || !m_db->get_block_undo(bh, u) || u.block_hash != best || !u.restorable()) {
                withhold("utxo-reorg-beyond-undo", "no restorable undo record for h=" + std::to_string(bh));
                return false;
            }
            uint256 prev;
            if (bh - 1 == m_assumed.base_height) {
                prev = m_assumed.base_hash;
            } else {
                BlockUndo pu;
                if (!m_db->get_block_undo(bh - 1, pu) || pu.block_hash.IsNull()) {
                    withhold("utxo-reorg-beyond-undo", "no undo record for h=" + std::to_string(bh - 1));
                    return false;
                }
                prev = pu.block_hash;
            }
            if (!m_cache->disconnect_from_undo(u) || !m_cache->flush(prev, bh - 1)) {
                withhold("utxo-rewind-failed", "h=" + std::to_string(bh));
                return false;
            }
            m_db->remove_block_undo(bh);
            ++m_rewinds;
            LOG_WARNING << "[EMB-DASH] UTXO rewind: h=" << bh << " " << best.GetHex().substr(0, 16)
                        << " left the header chain's best; best is now h=" << (bh - 1);
            if (m_bs.active) restart_fill();
        }
    }

    void start_fill(uint32_t best_h)
    {
        if (m_bs.active) return;
        m_bs.active = true;
        m_bs.next_height = best_h + 1;
        m_bs.next_request = best_h + 1;
        m_bs.end_height = best_h;
        m_bs.processed = 0;
        m_bs.total = 0;
        m_bs.last_drain_time = now_();
        schedule_stall_tick();
    }

    /// The best moved back (rewind): fill again from best+1, keeping only
    /// bodies above it (each is re-checked against the header chain).
    void restart_fill()
    {
        const uint32_t best_h = m_cache->get_best_height();
        m_bs.next_height = best_h + 1;
        m_bs.next_request = best_h + 1;
        for (auto it = m_bs.buffer.begin(); it != m_bs.buffer.end();)
            it = (it->first <= best_h) ? m_bs.buffer.erase(it) : std::next(it);
        m_dead_sends.clear();
    }

    void fill_step()
    {
        if (!m_bs.active) return;
        service_bootstrap();
        bool drained_any = false;
        while (!m_withheld && m_bs.buffer.count(m_bs.next_height)) {
            auto node = m_bs.buffer.extract(m_bs.next_height);
            auto& [b, bh] = node.mapped();
            const FullConnect res = connect_full(b, m_bs.next_height, bh);
            if (res == FullConnect::Connected) {
                drained_any = true;
                ++m_bs.next_height;
                ++m_bs.processed;
                m_bs.last_drain_time = now_();
                continue;
            }
            if (res == FullConnect::Dropped) reask(m_bs.next_height);
            break;
        }
        if (m_withheld) {
            m_bs.active = false;
            m_bs.buffer.clear();
            if (m_stall_timer) m_stall_timer->cancel();
            return;
        }
        if (m_bs.next_request < m_bs.next_height) m_bs.next_request = m_bs.next_height;
        while (m_bs.next_request <= m_bs.end_height
               && (m_bs.next_request - m_bs.next_height) < m_bs.window) {
            if (!m_bs.buffer.count(m_bs.next_request))
                request_block(m_bs.next_request);
            ++m_bs.next_request;
        }
        static int fill_log = 0;
        if (drained_any && (++fill_log % 50 == 0 || m_bs.next_height > m_bs.end_height)) {
            LOG_INFO << "[EMB-DASH] UTXO full catch-up: best=" << m_cache->get_best_height()
                     << " target=" << m_bs.end_height << " buf=" << m_bs.buffer.size()
                     << " dead=" << m_dead_sends.size();
        }
        if (m_bs.next_height > m_bs.end_height) {
            m_bs.active = false;
            m_dead_sends.clear();
            if (m_stall_timer) m_stall_timer->cancel();
            LOG_INFO << "[EMB-DASH] UTXO full set at the tip: best=" << m_cache->get_best_height()
                     << " " << m_cache->get_best_block().GetHex().substr(0, 16)
                     << " (" << m_bs.processed << " blocks connected this fill)";
        }
        if (drained_any) recompute_fees();
    }

    FullConnect connect_full(const BlockType& block, uint32_t height, const uint256& block_hash)
    {
        if (m_hash_at) {
            const auto hh = m_hash_at(height);
            if (hh && *hh != block_hash) {
                ++m_bad_bodies;
                return FullConnect::Dropped;
            }
        }
        if (block.m_previous_block != m_cache->get_best_block()) {
            if (!rewind_to_best_chain()) return FullConnect::Refused;
            if (m_cache->get_best_height() + 1 != height) return FullConnect::Rewound;
            if (block.m_previous_block != m_cache->get_best_block()) {
                ++m_bad_bodies;
                return FullConnect::Dropped;
            }
        }
        // BIP30 and the is_spent()-shaped output, before anything is touched.
        for (size_t t = 0; t < block.m_txs.size(); ++t) {
            const auto& tx = block.m_txs[t];
            const uint256 txid = dash_txid(tx);
            for (uint32_t i = 0; i < static_cast<uint32_t>(tx.vout.size()); ++i) {
                const auto& out = tx.vout[i];
                if (::core::coin::is_unspendable(out.scriptPubKey)) continue;
                if (out.value == 0 && out.scriptPubKey.m_data.empty())
                    return refuse_strict(height, "utxo-spent-shaped-output",
                                         "txid=" + txid.GetHex() + " vout=" + std::to_string(i) +
                                             " has value 0 and an empty script");
                if (m_cache->have_coin(Outpoint(txid, i)))
                    return refuse_strict(height, "bad-txns-BIP30",
                                         "txid=" + txid.GetHex() + " vout=" + std::to_string(i) +
                                             " is already a coin");
            }
        }
        UtxoViewCache::StrictRefusal why;
        auto undo = m_cache->connect_block(
            block, height, [](const MutableTransaction& tx) { return dash_txid(tx); },
            block_hash, /*strict=*/true, &why);
        if (!undo)
            return refuse_strict(height, "bad-txns-inputs-missingorspent",
                                 "txid=" + why.txid.GetHex() + " tx=" + std::to_string(why.tx_index) +
                                     " missing=" + why.missing.txid.GetHex() + ":" +
                                     std::to_string(why.missing.index));
        if (m_db) m_db->put_block_undo(height, *undo);
        if (!m_cache->flush(block_hash, height)) {
            withhold("utxo-flush-failed", "h=" + std::to_string(height));
            return FullConnect::Refused;
        }
        m_cache->prune_undo(height, DASH_MIN_BLOCKS_TO_KEEP);
        if (m_pool) m_pool->remove_for_block(block);
        ++m_full_connected;
        return FullConnect::Connected;
    }

    /// First refusal at a height: the body is asked again. A second one means
    /// the set is wrong: withhold.
    FullConnect refuse_strict(uint32_t height, const std::string& name, const std::string& detail)
    {
        ++m_strict_refusals;
        LOG_ERROR << "[EMB-DASH] STRICT REFUSAL h=" << height << " " << name << " " << detail;
        if (m_refused_heights.insert(height).second) {
            reask(height);
            return FullConnect::Refused;
        }
        withhold("utxo-strict-refusal", name + " h=" + std::to_string(height) + " " + detail);
        return FullConnect::Refused;
    }

    /// Ask a height of the fill again; it counts as requested, so the refill
    /// does not ask it a second time.
    void reask(uint32_t height)
    {
        request_block(height);
        if (m_bs.active && m_bs.next_request <= height) m_bs.next_request = height + 1;
    }

    void withhold(const std::string& event, const std::string& detail)
    {
        if (m_withheld) return;
        m_withheld = true;
        m_withheld_reason = event + ": " + detail;
        LOG_ERROR << "[EMB-DASH] UTXO full set WITHHELD (" << m_withheld_reason
                  << "): the set stops advancing; templates carry no mempool tx until the operator acts";
        if (m_alert) m_alert(event, detail);
    }

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

    /// Returns whether the request reached the wire. A dead send is kept on
    /// m_dead_sends for retry_dead_sends(); a live one clears it.
    bool request_block(uint32_t height)
    {
        if (m_request_fn) {
            const bool sent = m_request_fn(height);
            if (sent) m_dead_sends.erase(height);
            else      m_dead_sends.insert(height);
            return sent;
        }
        static bool warned = false;
        if (!warned) {
            warned = true;
            LOG_WARNING << "[EMB-DASH] UTXO bootstrap wants block h=" << height
                        << " but no request seam is wired"
                           " (set_request_block_fn — the E1/E2a live-feed leg);"
                           " relying on inbound delivery only";
        }
        return false;
    }

    /// Re-ask every dead send still inside the outstanding window; drop the
    /// ones already drained or buffered.
    void retry_dead_sends()
    {
        if (m_dead_sends.empty()) return;
        const std::vector<uint32_t> pending(m_dead_sends.begin(),
                                            m_dead_sends.end());
        int recovered = 0;
        for (uint32_t h : pending) {
            if (h < m_bs.next_height || m_bs.buffer.count(h)) {
                m_dead_sends.erase(h);
                continue;
            }
            if (request_block(h)) ++recovered;
        }
        if (recovered > 0)
            LOG_INFO << "[EMB-DASH] Bootstrap: re-sent " << recovered
                     << " request(s) that had died locally, "
                     << m_dead_sends.size() << " still dead";
    }

    void schedule_stall_tick()
    {
        if (!m_stall_timer || !m_bs.active) return;
        m_stall_timer->expires_after(m_stall_interval);
        m_stall_timer->async_wait([this](const boost::system::error_code& ec) {
            if (ec || !m_bs.active) return;
            service_bootstrap();
            schedule_stall_tick();
        });
    }

    Clock::time_point now_() const { return m_now_fn ? m_now_fn() : Clock::now(); }

    std::unique_ptr<UtxoViewDB>    m_db;
    std::unique_ptr<UtxoViewCache> m_cache;
    Mempool*                       m_pool{nullptr};
    RequestBlockFn                 m_request_fn;
    BootstrapState                 m_bs;
    bool                           m_bootstrap_done{false};
    std::set<uint32_t>             m_dead_sends;
    std::function<Clock::time_point()> m_now_fn;
    std::unique_ptr<boost::asio::steady_timer> m_stall_timer;
    std::chrono::milliseconds      m_stall_interval{
        std::chrono::seconds(BootstrapState::STALL_CHECK_SEC)};

    // Full mode.
    Mode                           m_mode{Mode::Accrual};
    ::core::coin::AssumedBase      m_assumed;
    uint32_t                       m_min_base_height{0};
    HashAtFn                       m_hash_at;
    AlertFn                        m_alert;
    bool                           m_base_verified{false};
    bool                           m_withheld{false};
    std::string                    m_withheld_reason;
    std::set<uint32_t>             m_refused_heights;
    uint64_t                       m_full_connected{0};
    uint64_t                       m_strict_refusals{0};
    uint64_t                       m_bad_bodies{0};
    uint64_t                       m_rewinds{0};
};

} // namespace coin
} // namespace dash
