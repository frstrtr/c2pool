// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

#include "config.hpp"
#include "params.hpp"
#include "share.hpp"
#include "share_tracker.hpp"
#include "peer.hpp"
#include "messages.hpp"
#include "head_retention.hpp"        // v36-0.24 convergence: clean_tracker Guard predicate (F2 + #25B)
#include "share_fetch_failover.hpp"  // v36-0.24 convergence: parent-fetch failover memory (#25C)
#include "desired_request_pacer.hpp"   // futility backoff for the desired-request drain
#include "ingest_budget.hpp"            // inbound-share admission bounds + ancestor-walk depth bound
#include <pool/share_download.hpp>     // shared downloader helpers (build_stops)

#include <core/coin_params.hpp>
#include <core/tx_advertiser.hpp>
#include <pool/node.hpp>
#include <pool/sharechain_node.hpp>
#include <pool/protocol.hpp>
#include <core/message.hpp>
#include <core/reply_matcher.hpp>
#include <core/known_txs_eviction.hpp>
#include <sharechain/prepared_list.hpp>
#include <sharechain/pool_rate_head_select.hpp> // sharechain::select_pool_rate_head — dashboard pool-rate head selection (#1482)
#include <c2pool/storage/sharechain_storage.hpp>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <deque>
#include <memory>
#include <mutex>
#include <shared_mutex>
#include <random>
#include <thread>

namespace ltc
{
struct HandleSharesData;

/// Identity of the heap object a ShareType variant points at. Ownership on this
/// path is tracked by POINTER, never by hash: a duplicate share carries the same
/// hash as the copy the sharechain already owns but is a DIFFERENT allocation,
/// and freeing by hash would free the chain's object.
inline const void* share_ptr_id(const ShareType& s)
{
    return s.invoke_const([](auto* p) { return static_cast<const void*>(p); });
}

/// Relinquish ownership of the pointee WITHOUT freeing it — used after the
/// sharechain has adopted the object, so the batch destructor leaves it alone.
/// Keeps the variant's alternative index, only nulls the pointer (destroy() on a
/// null pointer is a no-op).
inline void share_release(ShareType& s)
{
    s.invoke([&s](auto* p) {
        using share_t = std::remove_pointer_t<decltype(p)>;
        s = static_cast<share_t*>(nullptr);
    });
}

/// Deterministic count of share objects freed as ORPHANS — deserialised shares
/// that no owner ever adopted. Production code never reads it; it is the oracle
/// the ownership regression test asserts on, because the ASAN CI leg runs with
/// ASAN_OPTIONS detect_leaks=0 and LeakSanitizer therefore cannot see the leak
/// class this fixes.
inline std::atomic<std::uint64_t>& orphan_share_destroy_counter()
{
    static std::atomic<std::uint64_t> n{0};
    return n;
}

/// Free a share this container still owns (i.e. the sharechain never took it).
/// A share_release()d slot holds nullptr and is skipped.
inline void destroy_orphan_share(ShareType& s)
{
    if (share_ptr_id(s) == nullptr) return;
    s.destroy();
    orphan_share_destroy_counter().fetch_add(1, std::memory_order_relaxed);
}

/// OWNING payload of one inbound sharereply.
///
/// ltc::ShareType is a std::variant of RAW POINTERS with manual lifetime
/// (sharechain/share.hpp: `new Args()` in load, freed only by an explicit
/// destroy()). The only container that ever frees a share is the sharechain
/// itself (ShareChain::remove / ~ShareChain). Before this type existed, every
/// deserialised share that was NOT adopted by the tracker was simply lost:
/// a reply that arrived after its 15 s request timeout, a reply whose request
/// was cancelled on disconnect, a batch dropped by the pending_adds cap, a
/// duplicate skipped in phase 2, a share whose phase-1 verification failed.
/// Those leaks have no erase path at all, which is the unbounded growth behind
/// the RSS self-abort.
///
/// Whoever takes an item out MUST either move it into a container that owns it
/// or share_release() it after the sharechain adopted it.
struct OwnedShares
{
    std::vector<ShareType> m_items;
    std::vector<chain::RawShare> m_raw_items;

    OwnedShares() = default;
    // Always held through a shared_ptr — never copied, never moved.
    OwnedShares(const OwnedShares&) = delete;
    OwnedShares& operator=(const OwnedShares&) = delete;
    OwnedShares(OwnedShares&&) = delete;
    OwnedShares& operator=(OwnedShares&&) = delete;
    ~OwnedShares() { for (auto& s : m_items) destroy_orphan_share(s); }
};

/// ReplyMatcher response type for a sharereply.
///
/// The payload is held by shared_ptr and NOT by value: core/reply_matcher.hpp
/// copies the response twice on the way to the callback (Matcher::got_response
/// takes it by value, ResponseWrapper::operator()(T result) takes it by value
/// again), so a value-type destructor here would double free. A null m_owned is
/// the normal empty response the matcher synthesises on timeout/cancel.
struct ShareReplyData
{
    std::shared_ptr<OwnedShares> m_owned;

    OwnedShares& owned()
    {
        if (!m_owned) m_owned = std::make_shared<OwnedShares>();
        return *m_owned;
    }
    std::size_t size() const { return m_owned ? m_owned->m_items.size() : 0; }
    bool empty() const { return size() == 0; }
};

class NodeImpl : public pool::SharechainNode<ltc::Config, ltc::ShareChain, ltc::Peer>
{

    using base_t = pool::SharechainNode<ltc::Config, ltc::ShareChain, ltc::Peer>;
    // Async share downloader:
    // ID = uint256 (matches sharereq id to sharereply id)
    // RESPONSE = parsed shares plus their original raw payloads
    // REQUEST args: req_id, peer, hashes, parents, stops
    using share_getter_t = ReplyMatcher::ID<uint256>
        ::RESPONSE<ltc::ShareReplyData>
        ::REQUEST<uint256, peer_ptr, std::vector<uint256>, uint64_t, std::vector<uint256>>;

protected:
    core::CoinParams m_coin_params;
    ltc::Handler m_handler;
    share_getter_t m_share_getter;
    ShareTracker m_tracker;
    std::unique_ptr<c2pool::storage::SharechainStorage> m_storage;

    // Global pool of known transactions, populated by remember_tx and coin daemon.
    // Protocol handlers look up tx hashes here when processing shares.
    //
    // ⚠ THREAD DISCIPLINE — IO-THREAD CONFINED, AND ONLY WEAKLY SO.
    // The remember_tx ingest (protocol_actual.cpp / protocol_legacy.cpp) inserts
    // here holding NO lock at all. That is tolerable only while every other
    // participant is the same io thread, because then the accesses are simply
    // serialised by being on one thread. Consequences:
    //
    //   * Every READER must be on the io thread. The F3 tx-completeness gate in
    //     send_shares reads this map, which is precisely why broadcast_share is
    //     reached via post_broadcast_share() from the mining-submit thread rather
    //     than called there directly — an off-thread read would race an unlocked
    //     std::map::emplace, the freed-memory / GP-fault class.
    //   * If a reader ever genuinely has to run off the io thread, taking a
    //     shared lock on the reader alone does NOT make it safe: a shared lock
    //     gives no protection against a writer that takes no lock. The
    //     remember_tx insert would have to come under the same lock first.
    //   * Residual, PRE-EXISTING and not addressed here: prune_shares() evicts
    //     from this map on the COMPUTE thread under the exclusive tracker lock,
    //     which the unlocked io-thread insert does not respect. That race exists
    //     independently of anything above and wants its own fix.
    std::map<uint256, coin::Transaction> m_known_txs;
    // Insertion-order recency sidecar for m_known_txs. Recorded at each NEW
    // remember_tx insert; consumed by prune_shares to evict OLDEST-first down to
    // m_max_known_txs instead of the old wholesale clear() (which dropped every
    // forwardable tx byte at once -> canonical "referenced unknown transaction"
    // disconnect). Tx-forwarding only; no consensus/mint state. See
    // core::evict_known_txs_to_cap (core/known_txs_eviction.hpp).
    std::deque<uint256> m_known_txs_order;

    // Thread pool for parallel share_init_verify (scrypt CPU work).
    // Keeps expensive crypto off the io_context thread.
    boost::asio::thread_pool m_verify_pool{4};

    // ── Async compute pipeline ──────────────────────────────────────────
    // think() runs on m_think_pool (1 thread) holding m_tracker_mutex exclusively.
    // The IO thread NEVER calls lock() — only try_to_lock(). If the mutex is
    // held by the compute thread, the IO thread defers the operation and continues
    // processing network I/O, keepalive timers, and stratum. This eliminates the
    // event loop freeze that previously caused all peers to timeout simultaneously.
    //
    // Synchronization contract:
    //   Compute thread: unique_lock(m_tracker_mutex)     — exclusive, blocking
    //   IO thread reads: shared_lock(try_to_lock)        — non-blocking, skip if busy
    //   IO thread writes: unique_lock(try_to_lock)       — non-blocking, queue if busy
    boost::asio::thread_pool m_think_pool{1};
    std::atomic<bool> m_think_running{false};
    std::atomic<bool> m_clean_running{false};
    mutable std::shared_mutex m_tracker_mutex;

    // ── think()/clean watchdog (mirrors btc/node) ────────────────────────
    // Best-effort recovery if a think()/clean cycle wedges while holding the
    // exclusive tracker lock (the unbudgeted Phase-1 reorg-walk storm, .157
    // 2026-06-19 19:53). The pre-existing io_context-liveness watchdog is BLIND
    // to this: the IO thread only ever try_to_locks, so io_context stays
    // responsive while the compute thread spins under the exclusive lock. This
    // watchdog keys on a compute-thread deadline instead — an atomic ns-deadline
    // polled by an IO-thread steady_timer that NEVER touches m_tracker_mutex
    // (it would itself block on the stuck compute thread). On expiry it logs +
    // dumps a backtrace, clears the deadline, and resets m_think_running so a
    // fresh cycle can be scheduled. It does NOT forcibly unwind the wedged
    // compute thread (unsafe); the stuck cycle, if it ever returns, finds the
    // flag already false and its idempotent IO-phase drain runs harmlessly.
    static constexpr int THINK_WATCHDOG_SECONDS = 30;
    // MAX_PENDING_ADDS caps the deferred queue so a stuck/slow think() cannot
    // grow memory without bound — over the cap new batches are dropped with a
    // LOG_WARNING backpressure message (peers re-advertise, so dropped shares
    // are re-requested later).
    static constexpr size_t MAX_PENDING_ADDS = 256;

    // ── Ingest admission bounds (RSS self-abort fix) ──────────────────────
    // MAX_PENDING_ADDS bounds the number of DEFERRED BATCHES. It does not bound
    // the size of a batch (one sharereply is up to 1000 shares; one unsolicited
    // `shares` message is bounded only by the 32 MiB socket cap), and it sits
    // DOWNSTREAM of the phase-1 verify backlog, which had no bound at all: every
    // share posted to m_verify_pool stays resident until scrypt gets to it, and
    // the pool drains ~4 threads * ~20 ms = ~200 shares/s while a single peer can
    // deliver replies far faster than that.
    //
    // MAX_INFLIGHT_SHARES = 8192 is ~40 s of verify-pool backlog, the same order
    // as THINK_WATCHDOG_SECONDS. More than that means the peer is outrunning what
    // this node can ever verify. A cold full-depth bootstrap is NOT hurt: it
    // arrives as sequential <=1000-share replies, each hop waiting on the
    // previous reply, so it self-paces at network RTT.
    // MAX_INFLIGHT_BYTES = 128 MiB is 8192 * a generous 16 KB raw share, ~2.5% of
    // the 5000 MB rss limit, and at most four max-size unsolicited messages.
    static constexpr std::size_t MAX_INFLIGHT_SHARES = 8192;
    static constexpr std::size_t MAX_INFLIGHT_BYTES  = 128u * 1024u * 1024u;
    // Charged for a share whose raw wire bytes were not kept (the legacy
    // `shares` path constructs HandleSharesData without them), so that path
    // cannot bypass the byte ceiling by reporting zero.
    static constexpr std::size_t INGEST_BYTES_FALLBACK_PER_SHARE = 4096;
    // How far into the deferred queue ONE admission attempt may look, and so
    // the most batches it may evict. admit_or_evict_oldest() SUMS the
    // reservation held by at most this many of the oldest entries and evicts
    // only if that sum covers the shortfall, so this bounds a scan, not a
    // destroy-and-retry loop: a single inbound message can never walk the whole
    // queue, and it can never destroy anything at all unless the exchange it is
    // paying for is fundable. When the shortfall is smaller, fewer go: the scan
    // stops at the first entry that closes it.
    static constexpr std::size_t MAX_ADMIT_EVICTIONS = 64;
    IngestBudget m_ingest_budget{MAX_INFLIGHT_SHARES, MAX_INFLIGHT_BYTES};
    std::atomic<int64_t>  m_think_deadline_ns{0};
    std::atomic<uint64_t> m_think_generation{0};
    std::unique_ptr<boost::asio::steady_timer> m_watchdog_timer;
    void arm_think_watchdog();
    void disarm_think_watchdog();

    // ── Lock-free stats snapshot ─────────────────────────────────────────
    // Published by think() on the compute thread under m_tracker_mutex.
    // Read by ALL consumers (sync_status, loading page, global_stats,
    // graph data, etc.) WITHOUT needing the tracker lock.
    //
    // This is the c2pool equivalent of p2pool's reactor-thread stats
    // variables: updated atomically each think() cycle, always available.
    // Eliminates the systemic "0/empty" data problem where 20+ callbacks
    // returned stale data whenever think() held the exclusive lock.
    struct TrackerSnapshot {
        int chain_count{0};
        int verified_count{0};
        int head_count{0};
        int orphan_shares{0};
        int dead_shares{0};
        int fork_count{0};
        double pool_hashrate{0};
        // Wall-clock seconds when pool_hashrate was last computed > 0. The web
        // set_pool_hashrate_fn applies a 600 s staleness bound on this so a
        // stalled think() (dead node) breaks the graph line instead of serving
        // a frozen value forever. 0 = never computed.
        int64_t pool_hashrate_ts{0};
    };
    void publish_snapshot() {
        TrackerSnapshot s;
        s.chain_count = static_cast<int>(m_tracker.chain.size());
        s.verified_count = static_cast<int>(m_tracker.verified.size());
        s.head_count = static_cast<int>(m_tracker.chain.get_heads().size());
        s.fork_count = s.head_count;

        // ── Dashboard pool hashrate (issue #1482) ────────────────────────────
        // Computed HERE, under the compute-thread exclusive tracker lock, so the
        // web set_pool_hashrate_fn reads a FRESH snapshot value instead of
        // try-locking the tracker and returning a cached last-good latch. That
        // latch emitted bit-identical repeats whenever the try-lock lost to a
        // think() chunk, and the web frozen-guard (kMaxIdenticalPoolRateRun) then
        // zeroed those runs into false 0-drops — the rectangular ltc.voidbind
        // graph. Head choice is the pure sharechain::select_pool_rate_head SSOT
        // (verified best when live, else the fastest live raw head). Display-only:
        // the vardiff retarget runs on the verified chain over TARGET_LOOKBEHIND
        // and never reads this snapshot.
        {
            const int64_t now_s = static_cast<int64_t>(
                std::chrono::duration_cast<std::chrono::seconds>(
                    std::chrono::system_clock::now().time_since_epoch()).count());
            const uint32_t sp = m_coin_params.share_period ? m_coin_params.share_period : 1u;
            const int display_lookbehind = static_cast<int>(3600u / sp);

            auto make_head = [&](const uint256& hh) -> sharechain::PoolRateHead {
                sharechain::PoolRateHead rh;
                rh.hash = hh;
                if (hh.IsNull() || !m_tracker.chain.contains(hh)) return rh;
                rh.height = static_cast<int32_t>(m_tracker.chain.get_height(hh));
                try {
                    auto& cd = m_tracker.chain.get(hh);
                    int64_t ts = 0;
                    cd.share.invoke([&](auto* sh) {
                        ts = static_cast<int64_t>(sh->m_timestamp);
                    });
                    // A future-dated newest share (ts > now) yields a NEGATIVE
                    // age; keep it verbatim -- it is maximally live, not dead.
                    // Only an undatable share (ts<=0) leaves the kUnknownAge
                    // default (the not-live sentinel). Issue #1482 blocker A.
                    if (ts > 0) rh.newest_share_age_s = now_s - ts;
                } catch (...) {}
                if (rh.height >= 3) {
                    int lb = rh.height - 1 < display_lookbehind
                                 ? rh.height - 1 : display_lookbehind;
                    try {
                        auto aps = m_tracker.get_pool_attempts_per_second(hh, lb, false);
                        rh.aps = static_cast<double>(aps.GetLow64());
                    } catch (...) {}
                }
                return rh;
            };

            sharechain::PoolRateHead verified;
            bool verified_present = false;
            if (!m_best_share_hash.IsNull() &&
                m_tracker.chain.contains(m_best_share_hash)) {
                verified = make_head(m_best_share_hash);
                verified_present = true;
            }
            std::vector<sharechain::PoolRateHead> raw_heads;
            for (const auto& kv : m_tracker.chain.get_heads())
                raw_heads.push_back(make_head(kv.first));

            uint256 sel = sharechain::select_pool_rate_head(
                verified, verified_present, raw_heads);

            double hr = 0.0;
            if (!sel.IsNull()) {
                if (verified_present && verified.hash == sel)
                    hr = verified.aps;
                else
                    for (const auto& rh : raw_heads)
                        if (rh.hash == sel) { hr = rh.aps; break; }
            }
            if (hr > 0.0) {
                s.pool_hashrate = hr;
                s.pool_hashrate_ts = now_s;
            }
        }

        std::lock_guard<std::mutex> lock(m_snapshot_mutex);
        // Carry the last-good pool hashrate forward when this cycle produced none
        // (empty/short chain), so a transient gap does not blank the graph; the
        // web fn applies the 600 s staleness bound on pool_hashrate_ts to break
        // the line if think() itself has stalled.
        if (s.pool_hashrate <= 0.0 && m_snapshot.pool_hashrate > 0.0) {
            s.pool_hashrate = m_snapshot.pool_hashrate;
            s.pool_hashrate_ts = m_snapshot.pool_hashrate_ts;
        }
        m_snapshot = s;
    }
    mutable std::mutex m_snapshot_mutex;
    TrackerSnapshot m_snapshot;

    // ── Lock-free peer-info snapshot (display-only) ──────────────────────
    // m_peers / m_outbound_addrs are IO-thread-owned with NO lock; the
    // dashboard peer panel (set_peer_info_fn -> /peer_list, /peer_versions, …)
    // is served from the WebServer. Iterating those std::maps off the IO
    // thread while handle_version inserts / error()+close_connection erase
    // rebalances the tree under the reader's iterator -> freed-memory GP-fault
    // (back-port of the DASH #828 fix). So the JSON is BUILT on the IO thread
    // (publish_peer_info_snapshot, at every peer add/remove + the think
    // IO-phase for uptime freshness) and get_peer_info_json returns this copy
    // lock-free — it NEVER touches the live maps. Guarded by the existing
    // m_snapshot_mutex (held only for the swap; never nested with the tracker).
    nlohmann::json m_peer_info_snapshot = nlohmann::json::array();

    // Identity of the compute thread (m_think_pool's single thread).
    // Used by TrackerReadGuard to skip shared_lock when the caller is
    // already on the compute thread (which holds exclusive lock).
    std::atomic<std::thread::id> m_compute_thread_id{};

    // Pending share batches queued while think() holds the mutex.
    // Drained on the IO thread after think() releases the lock.
    // Uses unique_ptr because HandleSharesData is forward-declared here.
    struct PendingShareBatch {
        std::unique_ptr<HandleSharesData> data;
        NetService addr;
    };
    std::vector<PendingShareBatch> m_pending_adds;

    // Top-5 scored heads from last think() — used by clean_tracker()
    // to protect the best chains from head pruning (p2pool node.py:363).
    std::vector<uint256> m_last_top5_heads;

    // Restart-reorg supersede hint from the last think()/clean cycle
    // (ShareTracker::compute_supersede_hint). When active it names a genuine
    // higher-work fork the node is converging onto after a warm restart; used
    // by clean_tracker() to exempt the converging challenger segment from
    // stale-head eating and tail-dropping so its verification is not thrown
    // away and restarted every ~300s (which would re-create the original
    // stuck-on-persisted-head latch). Inactive on a healthy node.
    ltc::SupersedeHint m_supersede_hint;

    // ── Supersede-convergence liveness (tip-freeze livelock fix) ──────────
    // The restart-reorg elevated verify budget assumes the challenger segment
    // will eventually verify to CHAIN_LENGTH and the Phase-3 argmax will flip.
    // That assumption fails when the challenger's missing parent is UNOBTAINABLE
    // — no connected peer still retains it (its retention window has moved past
    // that share). Then the challenger's verified height never advances,
    // compute_supersede_hint re-arms it every cycle, and think() draws the
    // elevated scrypt budget on the same never-winning shares forever: an
    // infinite treadmill that holds the exclusive tracker lock for minutes,
    // during which the IO serve path (handle_get_share, try_to_lock) returns
    // EMPTY and inbound share batches are back-pressure dropped — the node
    // refuses exactly the inputs that would advance/unfreeze its tip (the F4
    // majority-deadlock pattern). We detect zero forward progress over
    // SUPERSEDE_STALL_LIMIT consecutive cycles and denylist the segment (keyed
    // by its stable target_segment_last) for SUPERSEDE_DENYLIST_TTL, which
    // deactivates the hint — stopping the treadmill AND re-enabling GC of the
    // zombie segment (clean_tracker's Guard-1b / tail-drop exemptions stop
    // matching an inactive hint). A later-obtainable parent retries after TTL.
    struct SupersedeProgress { int32_t last_acc_height{-1}; int stall_cycles{0}; };
    std::map<uint256, SupersedeProgress> m_supersede_progress;
    std::map<uint256, std::chrono::steady_clock::time_point> m_supersede_denylist;
    static constexpr int SUPERSEDE_STALL_LIMIT = 20;
    static constexpr std::chrono::minutes SUPERSEDE_DENYLIST_TTL{60};
    // Deactivate the hint if the challenger segment is proven unconvergeable
    // (already denylisted, or freshly stalled this call). Compute-thread only,
    // called under the exclusive tracker lock. Returns the (possibly cleared) hint.
    ltc::SupersedeHint gate_supersede_convergence(ltc::SupersedeHint hint);

    // Buffer of newly verified share hashes, flushed to LevelDB periodically
    std::vector<uint256> m_verified_flush_buf;

    // Buffer of pruned share hashes, batch-deleted from LevelDB after clean_tracker()
    std::vector<uint256> m_removal_flush_buf;

public:
    NodeImpl()
        : m_coin_params(ltc::make_coin_params(false)),
          m_share_getter(nullptr,
            [](uint256, peer_ptr, std::vector<uint256>, uint64_t, std::vector<uint256>){})
    {
        m_tracker.m_params = &m_coin_params;
        // pool::BaseNode's default ctor leaves these INDETERMINATE (see its
        // "todo: init" markers). Anything that null-checks them — e.g.
        // post_broadcast_share and broadcast_share — would otherwise read a
        // garbage pointer on this construction path. Null them here rather than
        // touch the shared base, which the other coin lanes also derive from.
        m_context = nullptr;
        m_chain = nullptr;
        m_config = nullptr;
        wire_chain_hooks();
    }

    NodeImpl(boost::asio::io_context* ctx, config_t* config)
        : m_coin_params(ltc::make_coin_params(config->m_testnet)),
          base_t(ctx, config),
          m_share_getter(ctx,
            [](uint256 req_id, peer_ptr to_peer,
               std::vector<uint256> hashes, uint64_t parents,
               std::vector<uint256> stops)
            {
                auto rmsg = ltc::message_sharereq::make_raw(req_id, hashes, parents, stops);
                to_peer->write(std::move(rmsg));
            },
            15)  // p2pool p2p.py:80: timeout=15 for share requests
    {
        m_tracker.m_params = &m_coin_params;

        // Seed addr store with hardcoded bootstrap peers
        m_addrs.load(config->pool()->m_bootstrap_addrs);
        // Randomise our nonce so we detect self-connections
        std::mt19937_64 rng(std::random_device{}());
        m_nonce = rng();
        // Route m_chain (used by BaseNode) to the tracker's main chain
        m_chain = &m_tracker.chain;

        // Open LevelDB storage and load any persisted shares
        std::string net_name = config->m_testnet ? "litecoin_testnet" : "litecoin";
        m_storage = std::make_unique<c2pool::storage::SharechainStorage>(net_name);
        load_persisted_shares();

        // Wire up verified-hash persistence callback (p2pool known_verified pattern)
        m_tracker.m_on_share_verified = [this](const uint256& hash) {
            m_verified_flush_buf.push_back(hash);
            if (m_verified_flush_buf.size() >= 50)
                flush_verified_to_leveldb();
        };

        // Wire up share removal → LevelDB cleanup + raw-cache eviction.
        wire_chain_hooks();
    }

private:
    /// Subscribe to ShareChain removal. Called from BOTH constructors so the
    /// default-ctor (unit-test) path exercises the same invariant.
    ///
    /// (a) p2pool main.py:269-270 — buffer removals for the LevelDB delete batch
    ///     that clean_tracker() flushes after drop-tails. Safe on crash:
    ///     unflushed shares get pruned at next startup by load_persisted_shares().
    /// (b) m_raw_share_cache had NO erase path anywhere. It was filled for every
    ///     distinct valid share ever seen (phase 2, before the dup check) and its
    ///     only would-be backstop lived in the never-called prune_shares(), so it
    ///     retained the full wire bytes of every share since boot — including all
    ///     the pruned challenger/fork shares. Tie its lifetime to chain
    ///     membership: when the owning chain drops a share, drop its raw bytes.
    ///     Fires on the compute thread under the exclusive tracker lock (the only
    ///     callers of chain.remove are think()/clean_tracker under it), and every
    ///     other toucher of m_raw_share_cache holds that mutex, so this is
    ///     race-free.
    ///
    /// REWARD-SAFE: m_raw_share_cache is a relay convenience (exact bytes as
    /// received); send_shares and the LevelDB persist path both fall back to
    /// pack(share) on a miss. A share that is no longer in the chain cannot be
    /// served or paid anyway.
    void wire_chain_hooks()
    {
        m_tracker.chain.on_removed([this](const uint256& hash) {
            m_removal_flush_buf.push_back(hash);
            m_raw_share_cache.erase(hash);
        });
    }

public:

    // INetwork: Pool node does not initiate disconnect — peer connections
    // manage their own lifecycle via close_connection()/error() below.
    void disconnect() override { }
    void connected(std::shared_ptr<core::Socket> socket) override;

    // ICommunicator (override BaseNode to track outbound lifecycle):
    void error(const message_error_type& err, const NetService& service, const std::source_location where = std::source_location::current()) override;
    void close_connection(const NetService& service) override;

    // BaseNode:
    void send_ping(peer_ptr peer) override;
    std::optional<pool::PeerConnectionType> handle_version(std::unique_ptr<RawMessage> rmsg, peer_ptr peer) override;

    // ltc
    void send_version(peer_ptr peer);
    /// Admit + phase-1 verify an inbound batch. Returns false when the
    /// ingest budget refused it (nothing was posted; the batch is freed).
    /// Take the ingest reservation for one inbound batch, evicting the OLDEST
    /// deferred batch and retrying when the budget is full. See node.cpp for
    /// why the budget on its own starves the newest, tip-extending batches.
    bool admit_or_evict_oldest(std::size_t n, std::size_t admit_bytes, const NetService& addr);
    bool processing_shares(HandleSharesData& data, NetService addr);
    void processing_shares_phase2(HandleSharesData& data, NetService addr);
    /// Direct tracker access — compute-thread-only (already holds exclusive lock)
    /// or startup code (before compute thread exists).
    /// IO-thread code MUST use read_tracker() instead.
    ShareTracker& tracker() { return m_tracker; }
    const core::CoinParams& coin_params() const { return m_coin_params; }

    /// RAII guard for IO-thread tracker reads.
    /// - IO thread: acquires shared_lock(try_to_lock). Returns falsy if busy.
    /// - Compute thread: skips locking (exclusive already held). Always truthy.
    /// Guard lifetime = lock lifetime. No way to hold a dangling reference.
    class TrackerReadGuard {
        std::shared_lock<std::shared_mutex> lock_;
        ShareTracker& tracker_;
        bool ok_;
    public:
        TrackerReadGuard(std::shared_mutex& mtx, ShareTracker& t, bool on_compute)
            : lock_(mtx, std::defer_lock), tracker_(t)
        {
            if (on_compute) {
                ok_ = true;   // exclusive lock already held by caller
            } else {
                ok_ = lock_.try_lock();
            }
        }
        TrackerReadGuard(TrackerReadGuard&&) = default;
        TrackerReadGuard(const TrackerReadGuard&) = delete;
        TrackerReadGuard& operator=(const TrackerReadGuard&) = delete;
        TrackerReadGuard& operator=(TrackerReadGuard&&) = default;

        explicit operator bool() const { return ok_; }
        ShareTracker& operator*()  { return tracker_; }
        ShareTracker* operator->() { return &tracker_; }
    };

    /// True if the calling thread is the compute thread (m_think_pool).
    /// Compute thread already holds exclusive lock — shared_lock must be skipped.
    bool is_compute_thread() const {
        return std::this_thread::get_id() == m_compute_thread_id.load(std::memory_order_relaxed);
    }

    /// Preferred tracker accessor for IO-thread callbacks.
    /// Returns a guard that:
    ///   - On IO thread: acquires shared_lock(try_to_lock). Check `if (!guard)` before use.
    ///   - On compute thread: skips locking (exclusive lock already held). Always valid.
    TrackerReadGuard read_tracker() {
        return TrackerReadGuard(m_tracker_mutex, m_tracker, is_compute_thread());
    }

    /// Acquire shared (reader) lock on the tracker mutex — BLOCKING.
    /// Only for consensus-critical paths (share creation) where skipping is not acceptable.
    /// IO-thread callers: prefer read_tracker() (non-blocking) unless you MUST have the lock.
    std::shared_lock<std::shared_mutex> tracker_shared_lock() {
        return std::shared_lock<std::shared_mutex>(m_tracker_mutex);
    }

    // Async share download — response delivered to callback when sharereply arrives
    void request_shares(uint256 id, peer_ptr peer,
                        std::vector<uint256> hashes, uint64_t parents,
                        std::vector<uint256> stops,
                        std::function<void(ltc::ShareReplyData)> callback)
    {
        m_share_getter.request(id, callback, id, peer, hashes, parents, stops);
    }

    // Called from HANDLER(sharereply) to complete a pending async request
    void got_share_reply(uint256 id, ltc::ShareReplyData shares)
    {
        try { m_share_getter.got_response(id, shares); }
        catch (const std::invalid_argument&) { /* request already timed out */ }
    }

    std::vector<ltc::ShareType> handle_get_share(std::vector<uint256> hashes, uint64_t parents, std::vector<uint256> stops, NetService peer_addr);

    /// Broadcast a new best-block notification to all connected P2P peers.
    void broadcast_bestblock(const coin::BlockHeaderType& header) {
        for (auto& [nonce, peer] : m_peers)
            peer->write(message_bestblock::make_raw(header));
    }

    /// Rebuild the lock-free peer-info snapshot. IO-THREAD ONLY (reads the
    /// IO-owned m_peers / m_outbound_addrs). Called at every peer add/remove
    /// and on the think IO-phase. Publishes under m_snapshot_mutex so the
    /// dashboard reader (get_peer_info_json) never touches the live maps.
    void publish_peer_info_snapshot() {
        nlohmann::json arr = nlohmann::json::array();
        for (const auto& [nonce, peer] : m_peers) {
            if (!peer) continue;
            auto addr = peer->addr();
            bool incoming = (m_outbound_addrs.find(addr) == m_outbound_addrs.end());
            auto uptime_sec = std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::steady_clock::now() - peer->m_connected_at).count();
            arr.push_back({
                {"address", addr.to_string()},
                {"version", peer->m_other_subversion},
                {"incoming", incoming},
                {"uptime", uptime_sec},
                {"downtime", 0},
                {"web_port", 0}
            });
        }
        std::lock_guard<std::mutex> lock(m_snapshot_mutex);
        m_peer_info_snapshot = std::move(arr);
    }

    /// Return a JSON array of connected peer info for the /peer_list endpoint.
    /// Returns the IO-thread-published snapshot lock-free — it must NEVER
    /// iterate the live m_peers map (that races the IO thread's insert/erase
    /// -> freed-memory GP-fault; back-port of DASH #828).
    nlohmann::json get_peer_info_json() const {
        std::lock_guard<std::mutex> lock(m_snapshot_mutex);
        return m_peer_info_snapshot;
    }

    /// Register a callback invoked whenever a bestblock message is received
    /// from any peer (after relaying). Use this to trigger work refresh.
    void set_on_bestblock(std::function<void(const uint256&)> fn) { m_on_bestblock = std::move(fn); }

    /// Set the software version string announced to peers in P2P version messages.
    void set_software_version(std::string ver) { m_software_version = std::move(ver); }

    /// Send a set of shares (with any needed txs) to a single peer.
    /// Skips shares that originated from that peer, and shares whose new-tx
    /// bytes we do not hold (F3 tx-completeness gate).
    /// Returns the hashes ACTUALLY written to that peer; broadcast_share marks
    /// only those as shared (F2), so an abandoned or gated batch is retried.
    std::vector<uint256> send_shares(peer_ptr peer, const std::vector<uint256>& share_hashes);

    /// Broadcast a locally-generated (or newly-received) share to all peers.
    ///
    /// MUST be called on the io_context thread with NO tracker lock held by the
    /// calling thread. It takes a shared try-lock on m_tracker_mutex, and a
    /// std::shared_mutex refuses a shared lock to a thread that already holds it
    /// exclusively — so calling this from inside an exclusive-lock scope silently
    /// defers every single time and broadcasts nothing at all. Off-thread callers
    /// must use post_broadcast_share() instead.
    void broadcast_share(const uint256& share_hash);

    /// Queue broadcast_share() onto the io_context thread.
    ///
    /// This is the entry point for every caller that is NOT already on the io
    /// thread — in particular the stratum mining-submit path, which creates the
    /// local share while holding the tracker mutex EXCLUSIVELY. Two reasons:
    ///
    ///   1. Lock discipline. Deferring past the end of the caller's exclusive
    ///      scope is what makes broadcast_share's shared try-lock able to
    ///      succeed at all (see the note above).
    ///   2. m_known_txs thread confinement. The F3 tx-completeness gate in
    ///      send_shares READS m_known_txs, and the remember_tx ingest
    ///      (protocol_actual.cpp / protocol_legacy.cpp) WRITES it with no lock
    ///      whatsoever. That is only survivable while every reader and writer is
    ///      the same io thread. Broadcasting straight from the submit thread
    ///      would add a cross-thread reader racing an unlocked std::map::emplace
    ///      — the freed-memory / GP-fault class. Posting keeps the read on the
    ///      io thread and does not widen the existing exposure.
    void post_broadcast_share(const uint256& share_hash);

    /// Diagnostics for the lock discipline above: how many broadcast_share calls
    /// deferred on the tracker try-lock, and how many acquired it and proceeded.
    /// A deferred count that tracks share creation 1:1 with zero acquisitions is
    /// the signature of a caller holding the exclusive lock across the call.
    uint64_t broadcast_deferred_count() const { return m_broadcast_deferred.load(); }
    uint64_t broadcast_acquired_count() const { return m_broadcast_acquired.load(); }
    /// Incremented once per broadcast_share call that got all the way to the
    /// per-peer send_shares loop with a non-empty batch. This is the number that
    /// was pinned at ZERO in production while the mining-submit path called
    /// broadcast_share inline under its exclusive lock.
    uint64_t broadcast_reached_send_count() const { return m_broadcast_reached_send.load(); }

    /// Start downloading shares from a peer, beginning at `target_hash`.
    /// Recursively fetches parents until the chain is connected or CHAIN_LENGTH reached.
    /// `walk_depth` is how many shares the recursive ancestor walk that led
    /// here has already pulled; 0 for a fresh think()-originated request.
    void download_shares(peer_ptr peer, const uint256& target_hash, std::uint64_t walk_depth = 0);

    /// Drain up to DESIRED_REQUEST_BUDGET queued desired-share requests
    /// (m_pending_desired) per pass, reposting the remainder to the io_context
    /// so its watchdog pulse fires between chunks (half-2 boot io-freeze fix).
    /// IO thread only.
    void drain_pending_desired();

    /// Arm the timer for the next drain pass (idempotent while one is pending).
    /// Rate-caps the drain: the budget bounds work per pass, this bounds passes
    /// per second. IO thread only.
    void schedule_desired_drain();

    /// Return the hash of our tallest chain head, or uint256::ZERO if empty.
    uint256 best_share_hash();

    /// Peer-facing advertisement of our head (version handshake + timer
    /// re-announce ONLY — never work creation).  Returns the verified head
    /// when we have one, otherwise the tallest RAW head so a fresh peer can
    /// begin download_shares() before our verified chain exists.  ROOT-2: on a
    /// --genesis node whose verified chain is still empty at handshake,
    /// best_share_hash() advertises NULL and the peer never downloads;
    /// advertising the raw head breaks that deadlock.
    uint256 advertised_best_share();

    /// Re-push our advertised head to every connected peer, bypassing the
    /// broadcast_share() de-dup set.  Fired on best-change and once on a timer
    /// after the verified chain first becomes non-empty, so a peer that
    /// handshook during the empty window can still ingest our chain.
    void readvertise_best_share();

    /// Load persisted shares from LevelDB storage into the tracker.
    void load_persisted_shares();
    void flush_verified_to_leveldb();

    /// Graceful shutdown: flush pending verified/removal buffers to LevelDB.
    void shutdown();

    /// Start dialing outbound peers from AddrStore / bootstrap list.
    /// Maintains target outbound peer count active outbound connections.
    void start_outbound_connections();

    // ── have_tx / losing_tx advertisement (SEND side) ─────────────────────
    // c2pool was RECEIVE-ONLY for the p2pool tx-pool advertisement: the
    // protocol handlers ingest a peer's have_tx/losing_tx into
    // Peer::m_remote_txs, but we never advertised our OWN known-tx set. Every
    // canonical p2pool dashboard therefore rendered this node with txpool = 0
    // (real p2pool peers report 12k-16k), and peers could not tell which txs we
    // already hold, so remember_tx forwarded whole tx bodies needlessly.
    //
    // Canonical (p2pool python, p2pool/p2p.py): ONE full have_tx immediately
    // after the version handshake (p2p.py:276), then pure deltas off the
    // known_txs_var change events — added -> send_have_tx (p2p.py:243-248),
    // removed -> send_losing_tx (p2p.py:250-259), transitioned -> both in that
    // order (p2p.py:261-274). c2pool has no reactive variable, so
    // Peer::m_tx_advert reconstructs the per-peer view and each sweep emits the
    // diff; the sweep cadence mirrors node.py:298's 10s forget_old_txs loop.
    // See core/tx_advertiser.hpp for the full derivation and the wire bound.
    //
    // Header-inline to match the DASH lane (whose handle_version vtable body
    // must stay link-free for the rig-free KAT targets); this touches only
    // header-only message types plus peer->write.
    //
    // REWARD-SAFETY: tx hashes only. No consensus, share validation, subsidy,
    // coinbase, payee or won-block state is read or written here.
    void advertise_known_txs(peer_ptr only_peer = nullptr)
    {
        // m_known_txs is mutated by the COMPUTE thread inside prune_shares()
        // (core::evict_known_txs_to_cap) under the exclusive tracker lock. This
        // runs on the IO thread, so take the same NON-BLOCKING shared lock the
        // other IO-thread readers use (the #828 freed-memory GP-fault class)
        // and simply skip if the compute thread is mid-cycle — the next sweep
        // carries the identical delta 10s later.
        std::set<uint256> current;
        {
            std::shared_lock<std::shared_mutex> lk(m_tracker_mutex, std::try_to_lock);
            if (!lk.owns_lock())
                return;
            for (const auto& entry : m_known_txs)
                current.insert(entry.first);
        }

        // One clock reading for the whole sweep: run_tx_advert uses it both to
        // apply the per-peer min-emit interval (never two writes in flight on
        // one socket) and to stamp the peer after a send. IO-thread-local, so
        // Peer::m_tx_advert needs no locking.
        const auto now = std::chrono::steady_clock::now();

        auto advertise_one = [&current, now](const peer_ptr& p)
        {
            if (!p)
                return;
            core::run_tx_advert(
                p->m_tx_advert, current,
                [&p](const std::vector<uint256>& hashes)
                { p->write(ltc::message_have_tx::make_raw(hashes)); },
                [&p](const std::vector<uint256>& hashes)
                { p->write(ltc::message_losing_tx::make_raw(hashes)); },
                core::TX_ADVERT_MAX_HASHES_PER_MESSAGE, now);
        };

        if (only_peer)
        {
            advertise_one(only_peer);
            return;
        }
        // m_peers is IO-thread-owned and mutated only on this thread
        // (handle_version insert / error() erase), so plain iteration is safe.
        for (auto& entry : m_peers)
            advertise_one(entry.second);
    }


    /// Set desired number of outbound peers maintained by connection loop.
    /// A value of 0 disables outbound dialing.
    void set_target_outbound_peers(size_t count) { m_target_outbound_peers = count; }

    /// Set max total P2P peers (inbound + outbound).
    void set_max_peers(size_t count) { m_max_peers = count; }

    /// Set P2P ban duration (seconds).

    /// Set cache size limits for memory control.
    void set_cache_limits(size_t max_shared, size_t max_known_txs, size_t max_raw) {
        m_max_shared_hashes = max_shared;
        m_max_known_txs = max_known_txs;
        m_max_raw_shares = max_raw;
    }

    /// Set RSS memory limit in MB (abort if exceeded). Static because checked in process_shares.
    static void set_rss_limit_mb(long mb);

    /// Expose tracker mutex for IO-thread callbacks that access the tracker.
    /// Callers MUST use shared_lock(try_to_lock) — NEVER blocking lock().
    std::shared_mutex& tracker_mutex() { return m_tracker_mutex; }

    /// Evict the unbounded per-node caches down to their configured limits.
    ///
    /// This is what was left of prune_shares() after its tail-drop loop was
    /// deleted: that loop duplicated clean_tracker Step 3, and prune_shares had
    /// NO CALL SITE at all, so the three cache_max_* operator knobs
    /// (cache_max_shared_hashes / cache_max_known_txs / cache_max_raw_shares)
    /// were inert and m_shared_share_hashes / m_known_txs grew for the life of
    /// the process. IO-THREAD ONLY: m_known_txs is written lock-free by
    /// remember_tx on the io thread (see the thread-discipline note above), so
    /// evicting from the compute thread would race that insert.
    void evict_caches_io_phase();

    /// Current ingest reservation (admitted batches not yet destroyed).
    /// Exposed for the heartbeat line so backpressure is visible on a live node.
    const IngestBudget& ingest_inflight() const { return m_ingest_budget; }

    /// Run the share tracker think() cycle: verifies chains, scores heads,
    /// identifies bad peers, and requests needed shares.
    /// Should be called periodically (e.g. after processing_shares or on a timer).
    void run_think();

    /// Fast-path: update best share after creating a local share.
    /// Bypasses run_think() scoring — just sets the new tip and triggers
    /// work refresh so miners immediately build on the new share.
    /// p2pool equivalent: set_best_share() → work_event.happened().
    void notify_local_share(const uint256& share_hash);

    /// Periodic maintenance: eat stale heads, drop tails, then run_think().
    /// Matches p2pool's clean_tracker() (node.py:355-402).
    void clean_tracker();

    /// Drain share batches queued while think() held the tracker mutex.
    /// Called on the IO thread after think() releases the lock.
    void drain_pending_adds();

    /// p2pool-style heartbeat: chain height, local/pool hashrate, orphan/DOA stats.
    /// Runs on a separate 30s timer — diagnostic only, not consensus-critical.
    void heartbeat_log();

    /// Set the block_rel_height function used by run_think() for chain scoring.
    /// fn(block_hash) should return confirmations from the coin daemon:
    ///   >= 0 : block is in main chain (0 = tip, higher = deeper)
    ///   <  0 : block is NOT in main chain (orphaned/stale)
    using block_rel_height_fn_t = std::function<int32_t(uint256)>;
    void set_block_rel_height_fn(block_rel_height_fn_t fn) { m_block_rel_height_fn = std::move(fn); }

    /// Lock-free stats snapshot — published by think(), never fails, never needs tracker lock.
    /// Inline definition must precede callers in the same header.
    TrackerSnapshot get_tracker_snapshot() const;
    int get_chain_count() const;
    int get_verified_count() const;

    /// Called when best_share changes (p2pool: new_work_event)
    /// Triggers immediate work update for all stratum miners.
    void set_on_best_share_changed(std::function<void()> fn) { m_on_best_share_changed = std::move(fn); }

    /// Callback to get local hashrate from stratum server (H/s)
    void set_local_hashrate_fn(std::function<double()> fn) { m_local_hashrate_fn = std::move(fn); }

    /// Local mining stats from RateMonitor (for p2pool-style status lines)
    struct LocalRateStats {
        double hashrate = 0;       // H/s (total local)
        double effective_dt = 0;   // seconds of data in window
        int total_datums = 0;      // pseudoshares in window
        int dead_datums = 0;       // dead (DOA) pseudoshares in window
    };
    void set_local_rate_stats_fn(std::function<LocalRateStats()> fn) { m_local_rate_stats_fn = std::move(fn); }

    /// Current PPLNS outputs {script_hex, satoshis} for payout display
    void set_current_pplns_fn(std::function<std::vector<std::pair<std::string, uint64_t>>()> fn) {
        m_current_pplns_fn = std::move(fn);
    }

    /// Node operator's payout script hex (for matching in PPLNS outputs)
    void set_node_payout_script_hex(const std::string& hex) { m_node_payout_script_hex = hex; }
    const std::string& get_node_payout_script_hex() const { return m_node_payout_script_hex; }

    /// Local miner scripts (from stratum sessions' pubkey_hashes → all script forms)
    void set_local_miner_scripts_fn(std::function<std::vector<std::string>()> fn) {
        m_local_miner_scripts_fn = std::move(fn);
    }

    /// Check whether a peer address is currently banned.

    /// ── Runtime admin API (pool peer bans + whitelist) ─────────────────
    /// All methods assumed to run on the io_context thread — callers
    /// (web_server HTTP handlers) dispatch via thread_safe_wrap().
    ///
    /// Returned JSON uses the shape:
    ///   {"ok": true|false, "error"?: "...", "bans": [...], "whitelist": [...]}
    nlohmann::json admin_whitelist_add(const std::string& host, uint16_t port);
    nlohmann::json admin_list_peers() const;
    nlohmann::json admin_drop_peer(const std::string& ip);
    nlohmann::json admin_dial_peer(const std::string& host, uint16_t port);

    /// Path to persisted whitelist file (~/.c2pool/pool_whitelist.json).
    /// Set by c2pool_refactored.cpp before start(); empty = no persistence.

    /// True if addr's IP matches a whitelist entry (IP or host:port).

protected:
    std::string m_software_version = "/c2pool:0.1/";  // overridden by set_software_version()
    std::function<void(const uint256&)> m_on_bestblock;
    std::function<void()> m_on_best_share_changed;
    std::function<double()> m_local_hashrate_fn;
    std::function<LocalRateStats()> m_local_rate_stats_fn;
    std::function<std::vector<std::pair<std::string, uint64_t>>()> m_current_pplns_fn;
    std::function<std::vector<std::string>()> m_local_miner_scripts_fn;
    std::string m_node_payout_script_hex;
    std::set<uint256> m_shared_share_hashes;  // de-dup set for broadcast_share
    std::set<uint256> m_rejected_share_hashes; // shares rejected by peers — never re-broadcast
    // broadcast_share tracker try-lock outcome counters (see the accessors above).
    std::atomic<uint64_t> m_broadcast_deferred{0};
    std::atomic<uint64_t> m_broadcast_acquired{0};
    std::atomic<uint64_t> m_broadcast_reached_send{0};
    std::set<uint256> m_downloading_shares;   // hashes currently being fetched

    // ---- half-2 boot io-freeze fix: budgeted parent-share request drain ----
    // A large persisted sharechain makes run_think's IO-phase produce a huge
    // result.desired. Draining it all synchronously monopolizes the io thread
    // and starves the io_context pulse (main_ltc.cpp watchdog: 5s pulse / 30s
    // freeze) -> abort during boot. Queue the desired requests here and drain
    // them in bounded passes, reposting the remainder so the pulse fires
    // between chunks. IO-THREAD CONFINED, same discipline as m_downloading_shares
    // above -- never touch off the io thread. Mirrors m_think_needs_continue.
    static constexpr std::size_t DESIRED_REQUEST_BUDGET = 50;
    // `depth` propagates the ancestor-walk length so the recursion in
    // download_shares can stop at the pruning zone instead of walking to
    // genesis (ltc::walk_may_continue). think()-originated entries start at 0.
    struct DesiredRequest { NetService addr; uint256 hash; std::uint64_t depth{0}; };
    std::deque<DesiredRequest> m_pending_desired;

    // ---- desired-drain RATE cap (the budget above is not one) ----
    // DESIRED_REQUEST_BUDGET bounds the work per PASS, and the continuation was
    // reposted with a bare asio::post — i.e. immediately. That buys interleaving
    // with other handlers but no rate limit at all: the queue is re-entered at
    // once, 50 requests per pass, for as long as it is non-empty. Because empty
    // replies leave result.desired unchanged, run_think refills the queue every
    // cycle and the drain never stops. Measured on the public LTC node after the
    // #1556 cutover: the io thread pinned at 98% CPU (ps -L: 1 thread R, 13 S)
    // and :8080 dead for 12.7 minutes while the process happily logged ~29
    // parent-share requests/s, 5137 distinct hashes, ~1:1 answered "empty".
    // #1556 removed the abort; it could not remove the burn.
    //
    // Space the passes with a timer instead. At 50 requests per pass this caps
    // the drain near 1000 req/s in the worst case while leaving the io thread
    // idle between passes, and in the failing shape above it cuts the burn by
    // the duty-cycle ratio. IO-THREAD CONFINED, like m_pending_desired.
    static constexpr std::chrono::milliseconds DESIRED_DRAIN_INTERVAL{50};
    std::unique_ptr<boost::asio::steady_timer> m_desired_drain_timer;
    bool m_desired_drain_scheduled{false};

    // Hard ceiling on the queue. result.desired is authoritative and replaces the
    // queue each think(), so a pathological set cannot accumulate across cycles —
    // but it CAN arrive huge in a single cycle on a large persisted sharechain.
    // Truncating costs nothing: the remainder is recomputed and re-queued next
    // cycle, now that the pacer keeps the futile members out of the way.
    static constexpr std::size_t DESIRED_QUEUE_MAX = 2000;

    // Per-hash futility backoff — the CAUSE-side half of the fix. See
    // desired_request_pacer.hpp for why this is not the same thing as the
    // per-(hash,peer) failover memory below. IO-THREAD CONFINED.
    ltc::DesiredRequestPacer<uint256> m_desired_pacer;

    // How many download_shares calls abandoned their request because the tracker
    // lock was held by think(). The stops build must not block the IO thread, so
    // a busy tracker costs us the request rather than a stall — this counts that
    // cost so throttling shows up as a number on a live node.
    std::atomic<uint64_t> m_stops_lock_busy{0};

    // v36-0.24 kr1z1s convergence hotfix #25(C): per-(hash,peer) parent-fetch
    // failure memory. Replaces the old peer-BLIND per-hash counter
    // (m_download_fail_count / MAX_EMPTY_RETRIES) which let a single black-hole
    // peer that answered "empty" starve every other peer that actually had the
    // parent. Now a peer is skipped only for the hash IT failed, we fail over to
    // other peers, prefer the advertiser, and back off only once EVERY peer has
    // failed (failures age out on a 90s TTL, so no per-think() reset is needed).
    //
    // Written on the IO thread (download_shares + the run_think dispatch loop);
    // read on the compute thread (clean_tracker Guard 2b, parent_abandoned).
    // m_fetch_failover_mtx guards BOTH the memory and the peer-key snapshot it is
    // queried against so the compute-thread read never races the IO-thread peer
    // map. Contention is negligible (a handful of hashes per cycle).
    std::mutex m_fetch_failover_mtx;
    ltc::FetchFailureMemory<uint256, NetService> m_fetch_failures;  // guarded by m_fetch_failover_mtx
    std::vector<NetService> m_peer_keys_snapshot;                   // guarded by m_fetch_failover_mtx

    // Refresh the peer-key snapshot from the live IO-owned m_peers map. MUST be
    // called on the IO thread. Takes m_fetch_failover_mtx.
    void refresh_peer_keys_snapshot()
    {
        std::vector<NetService> keys;
        keys.reserve(m_peers.size());
        for (const auto& [nonce, p] : m_peers)
            if (p) keys.push_back(p->addr());
        std::lock_guard<std::mutex> g(m_fetch_failover_mtx);
        m_peer_keys_snapshot = std::move(keys);
    }

    // True iff every currently-connected peer has recently failed to serve
    // `parent_hash` (clean_tracker Guard 2b input). Thread-safe; safe to call
    // from the compute thread. No peers / any peer not-yet-failed -> false.
    bool parent_fetch_abandoned(const uint256& parent_hash)
    {
        std::lock_guard<std::mutex> g(m_fetch_failover_mtx);
        return m_fetch_failures.abandoned(parent_hash, m_peer_keys_snapshot,
                                          static_cast<double>(std::time(nullptr)));
    }

    // Track req_id → peer addr for selective cancellation on disconnect.
    // p2pool has per-peer get_shares (GenericDeferrer), so connectionLost calls
    // respond_all() on just that peer's deferrer. c2pool has a shared m_share_getter,
    // so we track which req_ids belong to which peer for cancel-on-disconnect.
    std::map<uint256, NetService> m_pending_share_reqs;  // req_id → peer addr

    // Track recently-broadcast share hashes + timestamp so we can detect
    // rapid disconnections (peer rejected our share → PoW invalid loop).
    struct BroadcastRecord {
        std::vector<uint256> hashes;
        std::chrono::steady_clock::time_point when;
    };
    std::map<NetService, BroadcastRecord> m_last_broadcast_to; // per-peer

    // Connection maintenance
    static constexpr size_t DEFAULT_TARGET_OUTBOUND_PEERS = 8;
    size_t m_max_peers = 30;
    size_t m_target_outbound_peers = DEFAULT_TARGET_OUTBOUND_PEERS;
    std::unique_ptr<core::Timer> m_connect_timer;
    // Periodic have_tx/losing_tx delta sweep (core/tx_advertiser.hpp). Cadence
    // mirrors the canonical known-tx removal loop, node.py:298 t.start(10).
    std::unique_ptr<core::Timer> m_tx_advert_timer;
    std::unique_ptr<core::Timer> m_readvert_timer; // one-shot ROOT-2 re-advert
    std::set<NetService> m_pending_outbound;   // addresses currently being dialed
    std::set<NetService> m_outbound_addrs;     // successfully connected outbound peers

    // Peer banning: maps address → ban expiry time

    // IP-only manual bans (admin endpoint). Keyed by IP string so the
    // operator can ban/unban without knowing the peer's source port.

    // Whitelist: IPs that bypass is_banned() and host:port entries kept as
    // permanent dial targets. Persists across restart via m_whitelist_path.


    // Rate-limiting no longer needed: think() runs on a dedicated compute
    // thread (m_think_pool), serialized by m_think_running atomic flag.
    // The IO thread never blocks. p2pool's reactor.callLater equivalent.

    // Cache limits (configurable)
    size_t m_max_shared_hashes = 50000;
    size_t m_max_known_txs     = 10000;
    size_t m_max_raw_shares    = 50000;

    // Block depth function for chain scoring (set via set_block_rel_height_fn)
    block_rel_height_fn_t m_block_rel_height_fn;

    // Cached best share hash from the most recent think() cycle
    uint256 m_best_share_hash;

    // ROOT-2: fire exactly one delayed re-advert when the verified chain first
    // transitions from empty to non-empty (peers that handshook during the
    // empty window otherwise never see a best-change event).
    bool m_verified_was_empty = true;

    // Cache of original raw serialized bytes keyed by share hash.
    // Used for relay so we send the exact bytes we received, avoiding
    // any round-trip serialization differences.
    std::unordered_map<uint256, chain::RawShare, ShareHasher> m_raw_share_cache;
};

/// OWNING batch travelling the ingest pipeline: protocol handler -> admission ->
/// verify pool (phase 1) -> m_pending_adds -> phase 2.
///
/// Like OwnedShares, it frees every ShareType still held at destruction. Phase 2
/// calls share_release() on the items the sharechain ADOPTED, so exactly the
/// shares that found no owner — verify failures, duplicates, anything the
/// topological build dropped, and every share in a batch the pending_adds cap
/// dropped — are destroyed here instead of leaking.
///
/// Move-only, with HAND-WRITTEN move operations: a defaulted move would copy the
/// budget back-pointer into the target and leave it live in the source, so the
/// moved-from destructor would release the same reservation twice.
struct HandleSharesData
{
    std::vector<ShareType> m_items;
    std::vector<chain::RawShare> m_raw_items; // original raw bytes, parallel with m_items
    std::map<uint256, std::vector<coin::MutableTransaction>> m_txs;

    HandleSharesData() = default;
    HandleSharesData(const HandleSharesData&) = delete;
    HandleSharesData& operator=(const HandleSharesData&) = delete;

    HandleSharesData(HandleSharesData&& o) noexcept
        : m_items(std::move(o.m_items)),
          m_raw_items(std::move(o.m_raw_items)),
          m_txs(std::move(o.m_txs)),
          m_budget(o.m_budget),
          m_admitted_shares(o.m_admitted_shares),
          m_admitted_bytes(o.m_admitted_bytes)
    {
        o.m_items.clear();
        o.detach_budget();
    }

    HandleSharesData& operator=(HandleSharesData&& o) noexcept
    {
        if (this != &o)
        {
            free_owned();
            release_budget();
            m_items     = std::move(o.m_items);
            m_raw_items = std::move(o.m_raw_items);
            m_txs       = std::move(o.m_txs);
            m_budget          = o.m_budget;
            m_admitted_shares = o.m_admitted_shares;
            m_admitted_bytes  = o.m_admitted_bytes;
            o.m_items.clear();
            o.detach_budget();
        }
        return *this;
    }

    ~HandleSharesData()
    {
        free_owned();
        release_budget();
    }

    void add(const ShareType& share, std::vector<coin::MutableTransaction> txs)
    {
        m_items.push_back(share);
        m_raw_items.emplace_back(); // no cached raw bytes
        m_txs[share.hash()] = std::move(txs);
    }

    void add(const ShareType& share, std::vector<coin::MutableTransaction> txs,
             const chain::RawShare& raw)
    {
        m_items.push_back(share);
        m_raw_items.push_back(raw);
        m_txs[share.hash()] = std::move(txs);
    }

    /// Record the ingest reservation this batch holds; released by ~this.
    void attach_budget(IngestBudget* budget, std::size_t shares, std::size_t bytes)
    {
        m_budget = budget;
        m_admitted_shares = shares;
        m_admitted_bytes = bytes;
    }

    std::size_t admitted_shares() const { return m_admitted_shares; }
    std::size_t admitted_bytes()  const { return m_admitted_bytes; }

private:
    IngestBudget* m_budget{nullptr};
    std::size_t   m_admitted_shares{0};
    std::size_t   m_admitted_bytes{0};

    void free_owned()
    {
        for (auto& s : m_items) destroy_orphan_share(s);
        m_items.clear();
    }
    void release_budget()
    {
        if (m_budget) m_budget->release(m_admitted_shares, m_admitted_bytes);
        detach_budget();
    }
    void detach_budget()
    {
        m_budget = nullptr;
        m_admitted_shares = 0;
        m_admitted_bytes = 0;
    }
};


/*
    void handle_message_addrs(std::shared_ptr<pool::messages::message_addrs> msg, PoolProtocol* protocol);
    void handle_message_addrme(std::shared_ptr<pool::messages::message_addrme> msg, PoolProtocol* protocol);
    void handle_message_ping(std::shared_ptr<pool::messages::message_ping> msg, PoolProtocol* protocol);
    void handle_message_getaddrs(std::shared_ptr<pool::messages::message_getaddrs> msg, PoolProtocol* protocol);
    void handle_message_shares(std::shared_ptr<pool::messages::message_shares> msg, PoolProtocol* protocol);
    void handle_message_sharereq(std::shared_ptr<pool::messages::message_sharereq> msg, PoolProtocol* protocol);
    void handle_message_sharereply(std::shared_ptr<pool::messages::message_sharereply> msg, PoolProtocol* protocol);
    void handle_message_bestblock(std::shared_ptr<pool::messages::message_bestblock> msg, PoolProtocol* protocol);
    void handle_message_have_tx(std::shared_ptr<pool::messages::message_have_tx> msg, PoolProtocol* protocol);
    void handle_message_losing_tx(std::shared_ptr<pool::messages::message_losing_tx> msg, PoolProtocol* protocol);
    void handle_message_remember_tx(std::shared_ptr<pool::messages::message_remember_tx> msg, PoolProtocol* protocol);
    void handle_message_forget_tx(std::shared_ptr<pool::messages::message_forget_tx> msg, PoolProtocol* protocol);
*/

class Legacy : public pool::Protocol<NodeImpl>
{
public:
    void handle_message(std::unique_ptr<RawMessage> rmsg, NodeImpl::peer_ptr peer) override;

    ADD_HANDLER(addrs, ltc::message_addrs);
    ADD_HANDLER(addrme, ltc::message_addrme);
    ADD_HANDLER(ping, ltc::message_ping);
    ADD_HANDLER(getaddrs, ltc::message_getaddrs);
    ADD_HANDLER(shares, ltc::message_shares);
    ADD_HANDLER(sharereq, ltc::message_sharereq);
    ADD_HANDLER(sharereply, ltc::message_sharereply);
    ADD_HANDLER(bestblock, ltc::message_bestblock);
    ADD_HANDLER(have_tx, ltc::message_have_tx);
    ADD_HANDLER(losing_tx, ltc::message_losing_tx);
    ADD_HANDLER(remember_tx, ltc::message_remember_tx);
    ADD_HANDLER(forget_tx, ltc::message_forget_tx);
};

class Actual : public pool::Protocol<NodeImpl>
{
public:
    void handle_message(std::unique_ptr<RawMessage> rmsg, NodeImpl::peer_ptr peer) override;

    ADD_HANDLER(addrs, ltc::message_addrs);
    ADD_HANDLER(addrme, ltc::message_addrme);
    ADD_HANDLER(ping, ltc::message_ping);
    ADD_HANDLER(getaddrs, ltc::message_getaddrs);
    ADD_HANDLER(shares, ltc::message_shares);
    ADD_HANDLER(sharereq, ltc::message_sharereq);
    ADD_HANDLER(sharereply, ltc::message_sharereply);
    ADD_HANDLER(bestblock, ltc::message_bestblock);
    ADD_HANDLER(have_tx, ltc::message_have_tx);
    ADD_HANDLER(losing_tx, ltc::message_losing_tx);
    ADD_HANDLER(remember_tx, ltc::message_remember_tx);
    ADD_HANDLER(forget_tx, ltc::message_forget_tx);
};

using Node = pool::NodeBridge<NodeImpl, Legacy, Actual>;

} // namespace ltc