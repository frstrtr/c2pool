// SPDX-License-Identifier: AGPL-3.0-or-later
#include "node.hpp"
#include "share.hpp"
#include "mint_runloop.hpp"   // dash::mint::elect_best_share (election policy SSOT)
#include "known_txs_retention.hpp"  // dash::retain_template_txs / all_txs_backable (F1/F3)
#include "coin/transaction.hpp"  // coin::TX_WITH_WITNESS (remembered_tx_size, #950)
#include "think_gate.hpp"     // dash::think:: think-slot protocol + clean-cycle tip decision (#854)

#include <cassert>

#include <core/uint256.hpp>
#include <core/common.hpp>
#include <core/random.hpp>
#include <core/version_gate.hpp>   // core::version_gate::V36_ACTIVATION_VERSION (ratchet v36 guard)

#include <boost/asio/post.hpp>

#include <atomic>
#include <chrono>
#include <cstring>
#include <memory>
#include <vector>

// Dash p2pool sharechain pool-node — S8 pool-node reception, slice .4 (bodies).
//
// SLICE SCOPE (integrator-confirmed 2026-07-09, #656 a1444b4 branch-tip (awaiting merge tap)): the two
// link-deferred declarations from node.hpp — processing_shares() and
// handle_get_share() — get their REDUCED dash-native bodies here. "Reduced"
// means: the parallel X11 share_init_verify -> try_lock + m_tracker.add core,
// with think()/download/best-share/persist DEFERRED to their own later slices.
//
// This is a deliberate, non-1:1 port of src/impl/ltc/node.cpp. The DASH node is
// header-only and does NOT carry the ~8 LTC-only symbols the full ltc bodies
// touch (run_think/think, chain::PreparedList, m_raw_share_cache,
// m_best_share_hash, chain::get_reverse fork-logging, m_rejected_share_hashes,
// processing_shares_phase2 as a distinct TU method). Those are intentionally
// absent — force-fitting them would be scope creep. What remains is the minimal
// admit path that makes the Legacy/Actual dispatch (protocol_{legacy,actual}.cpp)
// actually reach the tracker: verify in parallel off the io_context, then insert
// under the non-blocking tracker lock on the io_context thread.

namespace dash
{

void NodeImpl::processing_shares(HandleSharesData& data_ref, NetService addr)
{
    // Take ownership immediately so the caller (the dispatch handler) can return
    // and free its local HandleSharesData.
    auto data = std::make_shared<HandleSharesData>(std::move(data_ref));
    size_t n = data->m_items.size();
    if (n == 0)
        return;

    // ── Phase 1 (m_verify_pool, parallel) ────────────────────────────────
    // Run share_init_verify() for each received share off the io_context thread.
    // DASH is X11 (~ms of CPU per share); the structural + PoW verify must NOT
    // block network I/O. Each share's hash computation is independent, so the
    // batch fully parallelises across the pool. A share that throws is left with
    // a null hash and skipped in phase 2.
    auto remaining = std::make_shared<std::atomic<int>>(static_cast<int>(n));
    for (size_t i = 0; i < n; i++)
    {
        boost::asio::post(m_verify_pool,
            [i, data, remaining, this, addr]()
            {
                auto& share = data->m_items[i];
                if (share.hash().IsNull())
                {
                    try
                    {
                        share.ACTION({
                            obj->m_hash = share_init_verify(*obj, m_tracker.m_coin_params, true);
                        });
                    }
                    catch (const std::exception&)
                    {
                        // leave hash null — phase 2 will skip this share
                    }
                }

                // Last verify done → hop back to the io_context thread for the
                // tracker insertion (writes stay single-threaded on io_context).
                if (--(*remaining) == 0)
                {
                    boost::asio::post(*m_context,
                        [data, this, addr]()
                        {
                            add_verified_shares(*data, addr);
                        });
                }
            });
    }
}

void NodeImpl::add_verified_shares(HandleSharesData& data, NetService addr)
{
    // io_context thread. Non-blocking tracker lock (architectural rule,
    // node.hpp): the compute thread (a later slice's think()) takes the
    // exclusive lock; the IO thread must NEVER block on it. If think() holds the
    // lock, defer this batch onto m_pending_adds — the compute thread drains it
    // after releasing. Until the think() slice lands nothing takes the exclusive
    // lock, so try_to_lock always succeeds here.
    {
        std::unique_lock lock(m_tracker_mutex, std::try_to_lock);
        if (!lock.owns_lock())
        {
            if (m_pending_adds.size() < MAX_PENDING_ADDS)
            {
                LOG_INFO << "[ASYNC-DEFER] add_verified_shares: tracker busy, queuing "
                         << data.m_items.size() << " shares from " << addr.to_string()
                         << " (pending=" << m_pending_adds.size() + 1 << ")";
                m_pending_adds.push_back(PendingShareBatch{
                    std::make_unique<HandleSharesData>(std::move(data)), addr});
            }
            else
            {
                LOG_WARNING << "[ASYNC-DEFER] add_verified_shares: pending queue full ("
                            << MAX_PENDING_ADDS << ") — dropping batch from "
                            << addr.to_string();
            }
            return;
        }
        // Lock held for the whole insertion below.

        int32_t new_count = 0;
        int32_t dup_count = 0;
        std::vector<c2pool::storage::SharechainStorage::ShareBatchEntry> db_batch;
        for (auto& share : data.m_items)
        {
            // Skip shares that failed phase-1 verification (hash still null).
            if (share.hash().IsNull())
            {
                // ShareVariants owns a heap Args* with no destructor; a share
                // that is never handed to m_tracker.add() must be freed here or
                // it leaks when HandleSharesData is destroyed.
                share.destroy();
                continue;
            }

            if (m_chain->contains(share.hash()))
            {
                ++dup_count;
                // Duplicate of a share the chain already owns: this incoming
                // copy is a distinct heap Args* that never reaches the tracker.
                share.destroy();
                continue;
            }

            m_tracker.add(share);
            ++new_count;

            // Collect for the atomic LevelDB batch persist (btc parity:
            // 8-byte version prefix + packed contents; committed after loop).
            if (m_storage && m_storage->is_available())
                collect_share_batch_entry(share, db_batch);
        }

        // Commit all shares atomically (one WriteBatch — crash-safe).
        if (!db_batch.empty() && m_storage && m_storage->is_available())
            m_storage->store_shares_batch(db_batch);

        if (new_count > 0)
        {
            auto as = addr.to_string();
            std::string source = (addr.port() == 0) ? as.substr(0, as.rfind(':')) : as;
            LOG_INFO << "Processing " << new_count << " shares from " << source
                     << "... (dup=" << dup_count
                     << " chain=" << m_tracker.chain.size() << ")";
        }

        // Lock released at scope exit; think() trigger below runs lock-free.
        if (new_count == 0)
            return;
    }

    // p2pool: set_best_share() after EVERY batch with new shares — think()
    // verifies, scores heads, and elects m_best_share_hash so minted shares
    // build on the live tip.
    run_think();
}

// Serialize one share into a LevelDB batch entry (btc node.cpp parity:
// [8B version LE][packed contents]; height slot carries absheight so the
// load path's height-ordered scan replays parents before children).
void NodeImpl::collect_share_batch_entry(
    ShareType& share,
    std::vector<c2pool::storage::SharechainStorage::ShareBatchEntry>& out)
{
    PackStream ps = pack(share);
    auto span = ps.get_span();
    uint64_t ver = share.version();
    std::vector<uint8_t> versioned;
    versioned.resize(8 + span.size());
    std::memcpy(versioned.data(), &ver, 8);
    std::memcpy(versioned.data() + 8,
                reinterpret_cast<const uint8_t*>(span.data()), span.size());

    share.invoke([&](auto* obj) {
        uint256 target = chain::bits_to_target(obj->m_bits);
        uint256 abswork_256;
        std::copy(obj->m_abswork.begin(), obj->m_abswork.end(), abswork_256.begin());
        c2pool::storage::SharechainStorage::ShareBatchEntry entry;
        entry.hash = obj->m_hash;
        entry.serialized_data = std::move(versioned);
        entry.prev_hash = obj->m_prev_hash;
        entry.height = obj->m_absheight;
        entry.timestamp = obj->m_timestamp;
        entry.work = abswork_256;
        entry.target = target;
        out.push_back(std::move(entry));
    });
}

std::vector<dash::ShareType>
NodeImpl::handle_get_share(std::vector<uint256> hashes, uint64_t parents,
                           std::vector<uint256> stops, NetService peer_addr)
{
    // try_to_lock per the architectural rule (node.hpp): the IO thread MUST
    // never block on m_tracker_mutex. An empty reply does not disconnect the
    // requesting peer — p2pool's downloader retries against another random peer,
    // so a busy-skip just shifts the request one iteration.
    std::shared_lock<std::shared_mutex> lock(m_tracker_mutex, std::try_to_lock);
    if (!lock.owns_lock())
    {
        static int defer_log = 0;
        if (defer_log++ % 50 == 0)
            LOG_INFO << "[handle_get_share] tracker busy — returning empty to "
                     << peer_addr.to_string()
                     << " (peer will retry against another peer)";
        return {};
    }

    if (hashes.empty())
        return {};

    parents = std::min(parents, (uint64_t)1000 / hashes.size());
    std::vector<dash::ShareType> shares;
    for (const auto& handle_hash : hashes)
    {
        if (!m_chain->contains(handle_hash))
        {
            static int miss_log = 0;
            if (miss_log++ < 5)
                LOG_WARNING << "[handle_get_share] hash NOT in chain: "
                            << handle_hash.ToString().substr(0, 16)
                            << " chain_size=" << m_chain->size();
            continue;
        }
        uint64_t n = std::min(parents + 1, (uint64_t)m_chain->get_height(handle_hash));
        for (auto [hash, data] : m_chain->get_chain(handle_hash, n))
        {
            if (std::find(stops.begin(), stops.end(), hash) != stops.end())
                break;
            shares.push_back(data.share);
        }
    }

    if (!shares.empty())
        LOG_INFO << "[Pool] Sending " << shares.size() << " shares to " << peer_addr.to_string();

    return shares;
}

// ════════════════════════════════════════════════════════════════════════════
// Run-loop mint slice (3/3) bodies — ports of the btc::NodeImpl prod
// reference (src/impl/btc/node.cpp), reconciled to the DASH pool-node.
// ════════════════════════════════════════════════════════════════════════════

void NodeImpl::init_storage(const std::string& net_name)
{
    if (m_storage)
        return;   // idempotent — run-loop calls once

    m_storage = std::make_unique<c2pool::storage::SharechainStorage>(net_name);

    // p2pool known_verified pattern: newly verified hashes buffer, flushed in
    // batches (and at shutdown).
    m_tracker.m_on_share_verified = [this](const uint256& hash) {
        m_verified_flush_buf.push_back(hash);
        if (m_verified_flush_buf.size() >= 50)
            flush_verified_to_leveldb();
    };

    // Pruned shares → batched LevelDB deletion (flushed at shutdown; unflushed
    // leftovers get pruned by the next startup's load_persisted_shares).
    m_tracker.chain.on_removed([this](const uint256& hash) {
        m_removal_flush_buf.push_back(hash);
        if (m_removal_flush_buf.size() >= 200 && m_storage && m_storage->is_available()) {
            m_storage->remove_shares_batch(m_removal_flush_buf);
            m_removal_flush_buf.clear();
        }
    });

    load_persisted_shares();
}

void NodeImpl::load_persisted_shares()
{
    if (!m_storage || !m_storage->is_available())
        return;

    auto all_hashes = m_storage->get_shares_by_height_range(0, UINT64_MAX);
    if (all_hashes.empty()) {
        LOG_INFO << "[Pool] No persisted DASH shares found in LevelDB";
        return;
    }

    // Only the newest window is loaded (LevelDB accumulates forever).
    const size_t keep = static_cast<size_t>(SharechainConfig::chain_length()) * 2 + 10;
    const size_t total_in_db = all_hashes.size();
    size_t skip = (total_in_db > keep) ? (total_in_db - keep) : 0;

    int loaded = 0, skipped = 0;
    std::vector<uint256> verified_hashes;
    for (size_t i = skip; i < total_in_db; ++i)
    {
        const auto& hash = all_hashes[i];
        std::vector<uint8_t> data;
        core::ShareMetadata meta;
        if (!m_storage->load_share(hash, data, meta) || data.size() < 8) {
            ++skipped;
            continue;
        }
        try {
            uint64_t ver;
            std::memcpy(&ver, data.data(), 8);
            chain::RawShare rshare(ver, PackStream(
                std::vector<unsigned char>(data.begin() + 8, data.end())));
            auto share = dash::load_share(rshare, NetService{"database", 0});
            // m_hash is not serialized — restore from the LevelDB key.
            share.ACTION({ obj->m_hash = hash; });
            if (m_chain->contains(share.hash())) {
                ++skipped;
                continue;
            }
            m_tracker.add(share);
            ++loaded;
            // Restore the cached X11 pow_hash (attempt_verify recomputes and
            // re-caches when missing).
            if (auto* idx = m_tracker.chain.get_index(hash); idx && !meta.pow_hash.IsNull())
                idx->pow_hash = meta.pow_hash;
            if (meta.is_verified)
                verified_hashes.push_back(hash);
        } catch (const std::exception& e) {
            LOG_WARNING << "[Pool] failed to load persisted share "
                        << hash.GetHex().substr(0, 16) << ": " << e.what();
        }
    }

    // Pre-populate the verified subset (p2pool node.py known_verified); the
    // height-ordered scan guarantees parent-before-child.
    int pre_verified = 0;
    for (const auto& vh : verified_hashes) {
        if (m_tracker.chain.contains(vh) && !m_tracker.verified.contains(vh)) {
            try {
                m_tracker.verified.add(m_tracker.chain.get_share(vh));
                ++pre_verified;
            } catch (...) {}
        }
    }

    LOG_INFO << "[Pool] Loaded " << loaded << " persisted DASH shares from LevelDB"
             << " (db_total=" << total_in_db << " window=" << keep
             << " pre_verified=" << pre_verified << " skipped=" << skipped << ")";

    // Prune everything older than the loaded window.
    if (skip > 0) {
        std::vector<uint256> prune(all_hashes.begin(),
                                   all_hashes.begin() + static_cast<long>(skip));
        m_storage->remove_shares_batch(prune);
        LOG_INFO << "[Pool] Pruned " << prune.size() << " old shares from LevelDB";
    }

    // Seed the best-share election + snapshot BEFORE the compute thread starts
    // (still single-threaded here — called once from the run loop pre-serving).
    // Without this, m_best_share_hash and TrackerSnapshot.best_share are null
    // until the FIRST think() finishes, and the first think()'s bootstrap
    // mass-verify holds the exclusive lock for seconds; over that window
    // best_share_hash()'s busy-fallback serves null → miners reconnecting at
    // restart get dead time (fail-closed — no bad payout — but avoidable). One
    // synchronous election over the just-loaded verified chain gives the tip
    // immediately. has_peers=false: no peers exist yet at load time, so the
    // election bootstraps off the verified/raw chain rather than refusing.
    m_best_share_hash =
        dash::mint::elect_best_share(m_tracker, m_best_share_hash, /*has_peers=*/false);
    publish_snapshot();
    if (!m_best_share_hash.IsNull())
        LOG_INFO << "[Pool] Seeded best share from persisted chain: "
                 << m_best_share_hash.GetHex().substr(0, 16);
}

void NodeImpl::flush_verified_to_leveldb()
{
    if (m_verified_flush_buf.empty() || !m_storage || !m_storage->is_available())
        return;
    std::vector<std::pair<uint256, uint256>> hash_pow_pairs;
    hash_pow_pairs.reserve(m_verified_flush_buf.size());
    for (const auto& hash : m_verified_flush_buf) {
        uint256 pow;
        if (auto* idx = m_tracker.chain.get_index(hash))
            pow = idx->pow_hash;
        hash_pow_pairs.emplace_back(hash, pow);
    }
    m_storage->mark_shares_verified_with_pow(hash_pow_pairs);
    m_verified_flush_buf.clear();
}

void NodeImpl::shutdown_persistence()
{
    // Teardown runs on the MAIN thread after ioc.run() returns, but a think()
    // cycle may still be in flight on the compute thread, mutating
    // m_verified_flush_buf / the chain under the exclusive lock (TSAN-captured
    // during the join-burst repro: flush_verified_to_leveldb() here racing
    // attempt_verify's m_on_share_verified push_back). Blocking here is fine —
    // the IO loop is already stopped, so the IO-never-blocks rule does not
    // apply; we just wait out the tail end of the last think() cycle.
    std::unique_lock lock(m_tracker_mutex);
    flush_verified_to_leveldb();
    if (!m_removal_flush_buf.empty() && m_storage && m_storage->is_available()) {
        m_storage->remove_shares_batch(m_removal_flush_buf);
        m_removal_flush_buf.clear();
    }
}

void NodeImpl::apply_min_protocol_ratchet()
{
    // Runtime wiring of the v36 accept-floor ratchet (auto_ratchet.hpp pure fns).
    // Structural mirror of dgb::NodeImpl::apply_min_protocol_ratchet (src/impl/dgb/
    // node.cpp:815), called at the same best-share-advance sites. Lifts the inbound
    // P2P accept-floor 1700 -> 3600 once the best share's DESIRED version holds
    // >= 95% of the work-weighted desired-version tally over the [9/10..10/10] window
    // behind the best share's parent — the SAME window the 60% successor gate reads
    // (version_negotiation.hpp). MUST run under the exclusive m_tracker_mutex.
    const uint32_t target  = SharechainConfig::NEW_MINIMUM_PROTOCOL_VERSION;  // 3600
    const uint32_t current =
        m_runtime_min_protocol_version.load(std::memory_order_relaxed);
    if (current >= target)                    // already ratcheted -> latched, no-op
        return;
    if (m_best_share_hash.IsNull() || !m_tracker.chain.contains(m_best_share_hash))
        return;

    // DASH DIVERGENCE FROM dgb (flagged for integrator): dgb keys the ratchet on the
    // best share's static TYPE version (35 -> 36 after the format switch). DASH has
    // NO v36 share TYPE — DashShare is permanently wire-type 16 — so "the best share
    // is v36" is expressed by its m_desired_version VOTE reaching 36, and that vote is
    // what the work-weighted tally is keyed by. Using the static type here would check
    // weights[16] (always ~100% pre-crossing) and FALSELY lift the floor; using the
    // vote checks weights[36], which is ~0 until the crossing actually happens.
    int64_t best_desired = 0;
    uint256 prev_hash;
    m_tracker.chain.get_share(m_best_share_hash).invoke([&](auto* obj) {
        best_desired = static_cast<int64_t>(obj->m_desired_version);
        prev_hash    = obj->m_prev_hash;
    });

    // SAFETY GUARD (DASH-specific): only a best share that itself desires v36 can lift
    // the floor. Without this, a fully-agreed pre-crossing chain (everyone desires 16)
    // would satisfy weights[best_desired=16] >= 95% and spuriously ratchet to 3600,
    // partitioning the pool from every legacy 1700 peer. dgb gets this for free because
    // its target floor is reachable only once the best share TYPE is already 36.
    if (best_desired < static_cast<int64_t>(
            core::version_gate::V36_ACTIVATION_VERSION))               // < 36
        return;

    if (prev_hash.IsNull() || !m_tracker.chain.contains(prev_hash))
        return;

    const int32_t CL = static_cast<int32_t>(SharechainConfig::chain_length());
    const int32_t parent_height = m_tracker.chain.get_height(prev_hash);

    // Sample the SAME window the 60% switch gate reads (version_negotiation.hpp
    // negotiation_window): anchor = nth_parent(parent, CHAIN_LENGTH*9/10),
    // size = CHAIN_LENGTH/10.
    const uint32_t window_start = (static_cast<uint32_t>(CL) * 9) / 10;
    const uint32_t window_size  =  static_cast<uint32_t>(CL) / 10;
    const uint256 anchor = m_tracker.chain.get_nth_parent_key(
        prev_hash, static_cast<int32_t>(window_start));
    auto weights = dash::version_negotiation::get_desired_version_weights(
        m_tracker.chain, anchor, window_size);

    // apply_min_protocol_ratchet_decision applies the full-window guard (parent_height
    // >= CHAIN_LENGTH) the pure ratchet omits, then delegates to the floor-divided 95%
    // work-weighted gate.
    const uint32_t lifted = dash::apply_min_protocol_ratchet_decision(
        parent_height, CL, weights, best_desired, current, target);
    if (lifted != current) {
        // Publish via the ATOMIC only. The IO-thread handshake (handle_version)
        // reads m_runtime_min_protocol_version.load() and composes it with the
        // operator knob (m_min_protocol_gate) via max(), so the ratcheted floor is
        // enforced immediately with NO data race on the plain-uint32 gate member
        // (which stays IO-thread-owned / operator-set).
        m_runtime_min_protocol_version.store(lifted, std::memory_order_relaxed);
        LOG_INFO << "[min-proto-ratchet] MINIMUM_PROTOCOL_VERSION " << current
                 << " -> " << lifted << " (>=95% window work desires v"
                 << best_desired << ", best="
                 << m_best_share_hash.GetHex().substr(0, 16) << ")";
    }
}

void NodeImpl::run_think()
{
    // THREAD-CONFINEMENT (enforced, not assumed — register_template_txs
    // precedent): the think-slot flags (m_think_running / m_rethink_pending)
    // are IO-thread-only. Every caller is on the single ioc.run() thread: the
    // mint hook (add_local_share), the reception path (add_verified_shares,
    // which posts itself back to m_context after the verify pool), the 2 s
    // advert drain, and both cycles' IO-phase epilogues. The compute thread
    // NEVER touches them — it only runs the tracker under the exclusive lock.
    // A compute-thread caller would break the "release then re-post" handshake
    // below (it would re-enter the slot it still owns), so trip loudly in
    // debug builds rather than let it be discovered in production.
    assert(!is_compute_thread() &&
           "run_think must not be called from the compute thread — the think "
           "slot (m_think_running/m_rethink_pending) is IO-thread-confined");

    // Serialize: only one think() in flight (compute pool has 1 thread).
    // #854: a skipped request is no longer DROPPED — acquire_think_slot()
    // records it in m_rethink_pending and the cycle that owns the slot
    // re-posts run_think() when it releases. Without that, a local mint or a
    // peer best-advert landing during a think/clean IO-phase (tracker lock
    // already released, flag still true) silently loses its re-election, so
    // the tip change never reaches the rigs until the 25 s keepalive.
    if (!dash::think::acquire_think_slot(m_think_running, m_rethink_pending)) {
        static int skip_log = 0;
        if (skip_log++ % 20 == 0)
            LOG_INFO << "[ASYNC-THINK] skipped — compute thread busy (re-think queued)";
        return;
    }
    if (!m_context) {
        // Rig-free (KAT/standalone) node: no IO context to hop back to, so
        // there is nowhere to post a queued re-think either — drop it.
        (void)dash::think::release_think_slot(m_think_running, m_rethink_pending);
        return;
    }

    auto block_rel_height = m_block_rel_height_fn
        ? m_block_rel_height_fn
        : std::function<int32_t(uint256)>([](uint256) -> int32_t { return 0; });

    boost::asio::post(m_think_pool, [this, block_rel_height]() {
        m_compute_thread_id.store(std::this_thread::get_id(), std::memory_order_relaxed);

        TrackerThinkResult result;
        bool best_changed = false;
        bool needs_continue = false;
        int64_t think_ms = 0;

        try {
            std::unique_lock lock(m_tracker_mutex);   // exclusive — IO defers

            // Bootstrap: no verified chain yet → verify everything in one
            // pass (p2pool think() runs synchronously during initial sync).
            const bool bootstrap = m_tracker.verified.size() == 0;
            auto t0 = std::chrono::steady_clock::now();
            result = m_tracker.think(block_rel_height,
                                     /*previous_block=*/uint256(),
                                     /*bits=*/0, bootstrap);
            think_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - t0).count();

            m_last_top5_heads = std::move(result.top5_heads);
            if (!result.best.IsNull()) {
                best_changed = (m_best_share_hash != result.best);
                m_best_share_hash = result.best;
                apply_min_protocol_ratchet();  // v36 accept-floor ratchet (dgb node.cpp:1526 parallel)
            }
            publish_snapshot();

            needs_continue = m_tracker.m_think_needs_continue
                          || m_tracker.m_think_walk_needs_continue;

            flush_verified_to_leveldb();
        } catch (const std::exception& e) {
            LOG_ERROR << "run_think() failed on compute thread: " << e.what();
        } catch (...) {
            LOG_ERROR << "run_think() failed on compute thread: unknown error";
        }
        // ── exclusive lock released ──

        LOG_INFO << "[ASYNC-THINK] compute done in " << think_ms << "ms"
                 << " best_changed=" << best_changed
                 << " needs_continue=" << needs_continue
                 << " bads=" << result.bad_peer_addresses.size()
                 << " desired=" << result.desired.size();

        boost::asio::post(*m_context, [this, result = std::move(result),
                                       best_changed, needs_continue]() {
          // #755 guard (ltc IO-phase parity, node.cpp:1580/1670): an exception
          // escaping this handler would propagate out of ioc.run() and
          // TERMINATE the node (Exit 134) — e.g. a chain-walk throw over a
          // fragmented/unrooted restart chain. Catch, log, and keep serving.
          try {
            // Ban peers that provided invalid/unverifiable shares (btc
            // node.cpp:1585-1603 port). Whitelisted bootstrap seeds are
            // immune (is_banned bypass); port-0 entries are database-loaded
            // addresses, not connectable peers.
            {
                const auto now = std::chrono::steady_clock::now();
                for (const auto& bad_addr : result.bad_peer_addresses) {
                    if (bad_addr.port() == 0)
                        continue;
                    LOG_WARNING << "run_think: banning peer " << bad_addr.to_string()
                                << " for unverifiable shares";
                    m_ban_list[bad_addr] = now + m_ban_duration;
                }
                // Expire old bans.
                for (auto it = m_ban_list.begin(); it != m_ban_list.end(); ) {
                    if (it->second <= now) it = m_ban_list.erase(it);
                    else ++it;
                }
                for (auto it = m_ip_ban_list.begin(); it != m_ip_ban_list.end(); ) {
                    if (it->second <= now) it = m_ip_ban_list.erase(it);
                    else ++it;
                }
            }

            // #754 share-download leg (p2pool node.py download loop; ltc
            // node.cpp:1600-1618 port): reset the per-cycle gate — p2pool
            // re-adds desired hashes from scratch every cycle with sleep(1)
            // backoff; permanent blacklisting stalls bootstrap — then request
            // each desired missing parent from a RANDOM peer.
            m_download_gate.new_cycle();
            drain_peer_best_adverts();
            if (!result.desired.empty() && !m_peers.empty()) {
                for (const auto& [peer_addr, hash] : result.desired) {
                    (void)peer_addr;  // oracle: random peer, not the reporter
                    auto peer_it = m_peers.begin();
                    if (m_peers.size() > 1)
                        std::advance(peer_it,
                            core::random::random_uint256().GetLow64() % m_peers.size());
                    download_shares(peer_it->second, hash);
                }
            }

            if (best_changed) {
                LOG_INFO << "[ASYNC-THINK] best=" << m_best_share_hash.GetHex().substr(0, 16)
                         << " — refreshing work + re-advertising";
                if (m_on_best_share_changed)
                    m_on_best_share_changed();
                // Re-announce our head so peers pull it (btc ROOT-2 parity).
                broadcast_share(m_best_share_hash);
            }

            drain_pending_adds();

            // #854: release_think_slot() reports whether a run_think() request
            // was dropped while this cycle held the slot — e.g. the mint that
            // drain_pending_adds()/add_local_share() just landed. Serve it, or
            // that share's election (and the miner notify it drives) is lost
            // until the next timer tick.
            const bool rethink_owed =
                dash::think::release_think_slot(m_think_running, m_rethink_pending);

            if (needs_continue || rethink_owed)
                boost::asio::post(*m_context, [this]() { run_think(); });
          } catch (const std::exception& e) {
            LOG_ERROR << "run_think() IO phase failed: " << e.what();
            if (dash::think::release_think_slot(m_think_running, m_rethink_pending))
                boost::asio::post(*m_context, [this]() { run_think(); });
          } catch (...) {
            LOG_ERROR << "run_think() IO phase failed: unknown error";
            if (dash::think::release_think_slot(m_think_running, m_rethink_pending))
                boost::asio::post(*m_context, [this]() { run_think(); });
          }
        });
    });
}

void NodeImpl::drain_pending_adds()
{
    if (m_pending_adds.empty())
        return;
    auto pending = std::move(m_pending_adds);
    m_pending_adds.clear();
    LOG_INFO << "[ASYNC-THINK] draining " << pending.size() << " deferred share batch(es)";
    for (auto& batch : pending)
        add_verified_shares(*batch.data, batch.addr);
}

// ════════════════════════════════════════════════════════════════════════════
// #754 share-download leg — faithful port of the PROVEN ltc downloader
// (src/impl/ltc/node.cpp:968-1105 download_shares, :1289-1327
// start_outbound_connections), coin-agnostic planning/gating shared via
// pool/share_download.hpp. This is what lets an EMPTY c2pool-dash node JOIN an
// established p2pool-dash sharechain: request the missing ancestors, insert
// them through the SAME processing_shares pipeline reception uses, and let
// think() root + verify the previously-orphaned live-pushed shares.
// ════════════════════════════════════════════════════════════════════════════

void NodeImpl::download_shares(peer_ptr peer, const uint256& target_hash)
{
    // C++ implementation of the p2pool share-download loop (ltc parity):
    //   1. de-dup + per-cycle fail gate (no re-request while in flight);
    //   2. RANDOM parent count 0..499 (oracle: random.randrange(500));
    //   3. STOPS list: known heads + their 10th parents (bounds the reply);
    //   4. on reply: feed processing_shares, then continue from the oldest
    //      received share's parent until the chain roots.
    if (target_hash.IsNull())
        return;
    if (!m_download_gate.try_begin(target_hash))
        return;  // already in flight, or failed out this think() cycle

    // p2pool: if len(self.peers) == 0: sleep(1); continue
    if (m_peers.empty()) {
        m_download_gate.abort(target_hash);
        return;
    }

    // Ask the supplied peer when it is still connected (the handshake-advert
    // path asks the ADVERTISING peer, oracle p2p.py handle_version →
    // handle_share_hashes); fall back to a random peer (oracle download loop:
    // peer = random.choice(self.peers.values()); ltc:1002-1007).
    if (!peer || !m_connections.contains(peer->addr())) {
        auto peer_it = m_peers.begin();
        if (m_peers.size() > 1)
            std::advance(peer_it,
                core::random::random_uint256().GetLow64() % m_peers.size());
        peer = peer_it->second;
    }

    // p2pool: parents=random.randrange(500)
    const uint64_t parents =
        core::random::random_uint256().GetLow64() % pool::download::PARENTS_RANGE;

    // stops need a tracker read — try_to_lock per the architectural rule (the
    // IO thread NEVER blocks on m_tracker_mutex). If think() holds it, skip;
    // the next think() cycle re-derives desired and retries.
    std::vector<uint256> stops;
    {
        std::shared_lock<std::shared_mutex> lock(m_tracker_mutex, std::try_to_lock);
        if (!lock.owns_lock()) {
            m_download_gate.abort(target_hash);
            return;
        }
        stops = pool::download::build_stops(m_tracker.chain);
    }

    const uint256 req_id = core::random::random_uint256();
    std::vector<uint256> hashes = { target_hash };

    // Track req_id → peer for selective cancellation on disconnect.
    m_pending_share_reqs[req_id] = peer->addr();

    LOG_INFO << "[Pool] Requesting parent share "
             << target_hash.ToString().substr(0, 16)
             << " from " << peer->addr().to_string()
             << " (parents=" << parents << " stops=" << stops.size() << ")";

    // weak_ptr prevents use-after-free if the peer disconnects before reply.
    std::weak_ptr<peer_t> weak_peer = peer;
    const auto peer_addr_for_log = peer->addr();

    request_shares(req_id, peer, hashes, parents, stops,
        [this, weak_peer, target_hash, peer_addr_for_log, req_id]
        (dash::ShareReplyData reply)
        {
            m_pending_share_reqs.erase(req_id);

            if (reply.m_items.empty())
            {
                // Empty reply = timeout, cancel, or peer had no match.
                const int fails = m_download_gate.on_empty(target_hash);
                LOG_INFO << "[Pool] Share request empty for "
                         << target_hash.ToString().substr(0, 16)
                         << " from " << peer_addr_for_log.to_string()
                         << " (fail " << fails << "/"
                         << pool::download::MAX_EMPTY_RETRIES << ")";
                return;
            }

            m_download_gate.on_success(target_hash);
            LOG_INFO << "[Pool] Received " << reply.m_items.size()
                     << " share(s) for download request "
                     << target_hash.ToString().substr(0, 16);

            // Feed the SAME reception pipeline live pushes ride: parallel
            // X11 verify → tracker insert → run_think (verify/root + next
            // desired set).
            HandleSharesData data;
            for (size_t idx = 0; idx < reply.m_items.size(); ++idx)
            {
                if (idx < reply.m_raw_items.size())
                    data.add(reply.m_items[idx], {}, reply.m_raw_items[idx]);
                else
                    data.add(reply.m_items[idx], {});
            }
            processing_shares(data, peer_addr_for_log);

            // Backfill continuation: oldest received share's parent still
            // unknown → keep pulling (ltc:1093-1102). This drives the full
            // history download without waiting one think() cycle per chunk.
            //
            // contains() reads the chain map — reader discipline: shared
            // lock (try_to_lock, IO thread never blocks). During the join
            // burst think() holds the exclusive lock most of the time, and
            // this callback fires on EVERY sharereply — the hottest of the
            // formerly-unlocked walks. Busy ⇒ queue the continuation on the
            // advert queue; the 2s advert timer / think()-IO-phase drain
            // re-checks under its own lock and resumes the backfill.
            const uint256 next = pool::download::oldest_parent(reply.m_items);
            if (!next.IsNull())
            {
                bool known = false;
                {
                    std::shared_lock<std::shared_mutex> lk(m_tracker_mutex,
                                                           std::try_to_lock);
                    if (!lk.owns_lock()) {
                        m_peer_best_adverts.emplace_back(weak_peer, next);
                        return;
                    }
                    known = m_chain->contains(next);
                }
                if (!known)
                {
                    if (auto locked = weak_peer.lock())
                        download_shares(locked, next);
                }
            }
        });
}

void NodeImpl::drain_peer_best_adverts()
{
    if (m_peer_best_adverts.empty())
        return;
    // contains() below reads the chain map — reader discipline: shared lock
    // (try_to_lock, IO thread never blocks). Busy ⇒ leave the queue intact;
    // the next 2s advert tick / think()-IO-phase drain retries. The lock is
    // scoped to the contains() partition only — download_shares()/run_think()
    // take their own locks.
    std::vector<std::pair<std::weak_ptr<peer_t>, uint256>> to_download;
    bool rethink = false;
    {
        std::shared_lock<std::shared_mutex> lk(m_tracker_mutex, std::try_to_lock);
        if (!lk.owns_lock())
            return;
        auto adverts = std::move(m_peer_best_adverts);
        m_peer_best_adverts.clear();
        for (auto& [weak_peer, best] : adverts)
        {
            if (weak_peer.expired())
                continue;
            if (m_chain->contains(best))
            {
                // Known share: re-run think() to re-evaluate the best chain
                // with the peer's perspective (ltc node.cpp:328-334 —
                // critical after restart, when LevelDB-loaded shares carry a
                // stale election).
                rethink = true;
                continue;
            }
            to_download.emplace_back(weak_peer, best);
        }
    }
    // #854 (was a TODO here): when drain_peer_best_adverts runs FROM the
    // think() IO-phase, m_think_running is still true, so this run_think()
    // cannot start a cycle. It is no longer a no-op — acquire_think_slot()
    // records the request in m_rethink_pending and the owning cycle re-posts
    // run_think() when it releases, so the re-election is guaranteed rather
    // than left to the next 2 s advert-timer tick.
    if (rethink)
        run_think();
    for (auto& [weak_peer, best] : to_download)
    {
        if (auto peer = weak_peer.lock())
            download_shares(peer, best);
    }
}

void NodeImpl::start_outbound_connections()
{
    if (!m_context)
        return;  // rig-free (KAT/standalone) node

    // ── have_tx / losing_tx delta sweep ──────────────────────────────────
    // Started before the outbound-dialing early-return below: a node with
    // outbound dialing disabled still accepts inbound peers and must still
    // advertise its tx pool to them. Advert-only, no consensus state.
    m_tx_advert_timer = std::make_unique<core::Timer>(m_context, true);
    m_tx_advert_timer->start(core::TX_ADVERT_INTERVAL_SECONDS,
                             [this]() { advertise_known_txs(); });

    // ── canonical addr-discovery sweep (p2p.py:794-799) ──────────────────
    // Also started before the dialing early-return: an inbound-only node needs to
    // learn addresses. Self-limiting — getaddrs_sweep() is a no-op once the
    // AddrStore reaches PREFERRED_ADDR_STORAGE (1000) or while we have no peers.
    m_getaddrs_timer = std::make_unique<core::Timer>(m_context, true);
    m_getaddrs_timer->start(20, [this]() { getaddrs_sweep(); });

    // Advert-drain pump: handle_version (inline, link-free for the KAT
    // targets) only QUEUES a peer's advertised best share; this timer is the
    // node.cpp-side consumer that turns the queue into sharereq dispatches.
    // 2s bounds the join latency; the check is O(1) when the queue is empty.
    m_advert_timer = std::make_unique<core::Timer>(m_context, true);
    m_advert_timer->start(2, [this]() {
        drain_peer_best_adverts();
        // IO thread: keep the display peer-info snapshot's uptimes fresh
        // (peer add/remove refresh it on membership change; this ticks it so
        // the dashboard card's uptime advances between events). Cheap — a few
        // peers — and it is the reader-safe alternative to the HTTP thread
        // ever touching m_peers directly.
        publish_peer_info_snapshot();
    });

    if (m_target_outbound_peers == 0)
    {
        LOG_INFO << "[Pool] Outbound peer dialing disabled (target=0)";
        return;
    }

    // btc/ltc node.cpp:1289-1327 port.
    auto try_connect_peers = [this]()
    {
        const size_t outbound = m_outbound_addrs.size();
        if (outbound >= m_target_outbound_peers || m_connections.size() >= m_max_peers)
            return;

        size_t needed = m_target_outbound_peers - outbound;
        // Ask for a few extra in case some are already connected.
        for (auto& ap : get_good_peers(needed + 4))
        {
            if (needed == 0)
                break;
            // Skip if already connected, already dialing, or banned.
            if (m_connections.contains(ap.addr) || m_pending_outbound.contains(ap.addr)
                || is_banned(ap.addr))
                continue;
            LOG_INFO << "[Pool] Dialing outbound peer " << ap.addr.to_string();
            m_pending_outbound.insert(ap.addr);
            core::Client::connect(ap.addr);
            --needed;
        }
    };

    try_connect_peers();  // initial burst (--addnode/--connect seeds)

    // Periodic maintenance — top up outbound peers every 30 seconds.
    m_connect_timer = std::make_unique<core::Timer>(m_context, true);
    m_connect_timer->start(30, try_connect_peers);
}

// ════════════════════════════════════════════════════════════════════════════
// clean_tracker — btc node.cpp:1878-2173 port (p2pool node.py:355-402:
// stale-head eating + tail dropping). Runs think + prune on the compute
// thread under the exclusive lock — chain modifications MUST NOT happen
// concurrently with think() or IO-thread reads. Scheduled by the run loop's
// periodic tick; without it the raw chain grows unbounded past
// 2*CHAIN_LENGTH+10.
// ════════════════════════════════════════════════════════════════════════════

void NodeImpl::clean_tracker()
{
    // Prevent concurrent clean_tracker (timer re-entry safety).
    if (m_clean_running.exchange(true))
        return;

    if (!m_context) {
        m_clean_running.store(false);
        return;   // rig-free (KAT/standalone) node
    }

    // Take the think slot, which also blocks run_think() re-entry for the
    // duration of the clean. #854: acquire_clean_slot() is a compare_exchange,
    // closing the load()-then-store() check-then-act window this prologue used
    // to carry as a TODO — the guard is now symmetric with the m_clean_running
    // exchange() above. A failure records NO pending re-think: the think cycle
    // that won the slot performs the same election clean's Step 1 would, and
    // the periodic timer retries the prune shortly.
    if (!dash::think::acquire_clean_slot(m_think_running)) {
        m_clean_running.store(false);
        return;
    }

    // Post the entire body to the compute thread: chain modifications happen
    // under the exclusive lock, never concurrent with think() or IO reads.
    boost::asio::post(m_think_pool, [this]() {
      m_compute_thread_id.store(std::this_thread::get_id(), std::memory_order_relaxed);

      bool clean_best_changed = false;
      bool bootstrap = false;
      try {
        std::unique_lock lock(m_tracker_mutex);  // exclusive

        // #854: the tip AS THE CLEAN CYCLE FOUND IT. clean_best_changed is
        // decided against this, not against the value Step 1 has already
        // written — otherwise an election absorbed by Step 1 (the case a mint
        // landing during a think IO-phase produces) makes Step 4's comparison
        // trivially false and no work is pushed to the rigs. Read under the
        // exclusive lock, on the compute thread, before either think() runs.
        const uint256 best_at_entry = m_best_share_hash;

        auto block_rel_height = m_block_rel_height_fn
            ? m_block_rel_height_fn
            : std::function<int32_t(uint256)>([](uint256) -> int32_t { return 0; });

        // Step 1: run think() inline (already holds the lock).
        {
            bootstrap = m_tracker.verified.size() == 0;
            auto result = m_tracker.think(block_rel_height,
                                          /*previous_block=*/uint256(),
                                          /*bits=*/0, bootstrap);
            m_last_top5_heads = std::move(result.top5_heads);
            if (!result.best.IsNull()) {
                m_best_share_hash = result.best;
                apply_min_protocol_ratchet();  // v36 accept-floor ratchet (dgb node.cpp:1905 parallel)
            }
            flush_verified_to_leveldb();
        }

        const auto now_sec = static_cast<int64_t>(std::time(nullptr));
        const auto CL = static_cast<int32_t>(SharechainConfig::chain_length());

        // Step 2: eat stale heads (p2pool node.py:358-378). Three guards
        // protect useful heads: top-5 scored, seen <300s ago, unverified
        // heads whose tail has recent (<120s) child activity.
        if (!m_last_top5_heads.empty())  // p2pool node.py:359: if decorated_heads:
        {
            std::set<uint256> top5_set(m_last_top5_heads.begin(), m_last_top5_heads.end());

            for (int iter = 0; iter < 1000; ++iter)
            {
                std::vector<uint256> to_remove;
                auto heads_copy = m_tracker.chain.get_heads();
                for (auto& [head_hash, tail_hash] : heads_copy)
                {
                    if (!m_tracker.chain.contains(head_hash)) continue;
                    if (top5_set.count(head_hash)) continue;             // guard 1
                    auto* idx = m_tracker.chain.get_index(head_hash);
                    if (!idx || idx->time_seen > now_sec - 300) continue; // guard 2
                    if (!m_tracker.verified.contains(head_hash))          // guard 3
                    {
                        auto& rev = m_tracker.chain.get_reverse();
                        auto rev_it = rev.find(tail_hash);
                        if (rev_it != rev.end() && !rev_it->second.empty())
                        {
                            int64_t max_child_ts = 0;
                            for (const auto& child : rev_it->second)
                            {
                                auto* cidx = m_tracker.chain.get_index(child);
                                if (cidx && cidx->time_seen > max_child_ts)
                                    max_child_ts = cidx->time_seen;
                            }
                            if (max_child_ts > now_sec - 120) continue;
                        }
                    }
                    to_remove.push_back(head_hash);
                }

                if (to_remove.empty()) break;

                for (const auto& h : to_remove)
                {
                    try {
                        if (m_tracker.verified.contains(h))
                            m_tracker.verified.remove(h, /*owns_data=*/false);
                        if (m_tracker.chain.contains(h))
                            m_tracker.chain.remove(h);
                    } catch (...) {}
                }
            }
        }

        // Step 3: drop tails — remove ALL children of tails whose every head
        // is at least 2*CHAIN_LENGTH+10 high (p2pool node.py:382-398; only
        // shares far beyond the PPLNS window are removed).
        {
            int total_dropped = 0;
            for (int iter = 0; iter < 1000; ++iter)
            {
                std::vector<uint256> to_remove;
                auto tails_copy = m_tracker.chain.get_tails();
                for (auto& [tail_hash, head_hashes] : tails_copy)
                {
                    int32_t min_height = 0;  // 0 → skip if no valid heads
                    for (auto& hh : head_hashes) {
                        if (!m_tracker.chain.contains(hh)) continue;
                        auto h = m_tracker.chain.get_height(hh);
                        if (min_height == 0 || h < min_height)
                            min_height = h;
                    }
                    if (min_height < 2 * CL + 10) continue;

                    // p2pool node.py:386: to_remove.update(reverse.get(tail))
                    auto& rev = m_tracker.chain.get_reverse();
                    auto rev_it = rev.find(tail_hash);
                    if (rev_it != rev.end()) {
                        for (const auto& child : rev_it->second)
                            to_remove.push_back(child);
                    }
                }

                if (to_remove.empty()) break;

                for (const auto& aftertail : to_remove)
                {
                    try {
                        if (!m_tracker.chain.contains(aftertail)) continue;
                        // p2pool node.py:393: previous_hash must still be a tail.
                        auto* idx = m_tracker.chain.get_index(aftertail);
                        if (!idx) continue;
                        if (!m_tracker.chain.get_tails().count(idx->tail))
                            continue;
                        if (m_tracker.verified.contains(aftertail))
                            m_tracker.verified.remove(aftertail, /*owns_data=*/false);
                        m_tracker.chain.remove(aftertail);
                        ++total_dropped;
                    } catch (...) {}
                }
            }
            if (total_dropped > 0)
                LOG_INFO << "[clean-drop-tails] dropped " << total_dropped << " shares"
                         << " chain_size=" << m_tracker.chain.size()
                         << " heads=" << m_tracker.chain.get_heads().size();
        }

        // Step 4: re-score after pruning (inline, still holding the lock).
        {
            auto result = m_tracker.think(block_rel_height,
                                          /*previous_block=*/uint256(),
                                          /*bits=*/0, bootstrap);
            m_last_top5_heads = std::move(result.top5_heads);
            if (!result.best.IsNull()) {
                m_best_share_hash = result.best;
                apply_min_protocol_ratchet();  // v36 accept-floor ratchet (dgb node.cpp:2077 parallel)
            }
            // #854: decide across BOTH thinks — entry tip vs exit tip. Placed
            // outside the IsNull() guard on purpose: if Step 1 elected a new
            // tip and Step 4's think returns nothing (e.g. everything it would
            // have scored was just pruned), m_best_share_hash still carries
            // Step 1's election and that IS a tip change the rigs must see.
            clean_best_changed =
                dash::think::clean_cycle_best_changed(best_at_entry, m_best_share_hash);
            publish_snapshot();
            flush_verified_to_leveldb();
        }

        // Step 5: flush pruned shares from LevelDB (p2pool main.py:269-270).
        if (!m_removal_flush_buf.empty() && m_storage && m_storage->is_available())
        {
            auto count = m_removal_flush_buf.size();
            if (m_storage->remove_shares_batch(m_removal_flush_buf))
                LOG_INFO << "[clean-leveldb] removed " << count << " pruned shares from LevelDB";
            else
                LOG_WARNING << "[clean-leveldb] batch remove failed, count=" << count;
            m_removal_flush_buf.clear();
        }
      } catch (const std::exception& e) {
        LOG_ERROR << "[CLEAN] failed on compute thread: " << e.what();
      } catch (...) {
        LOG_ERROR << "[CLEAN] failed on compute thread: unknown error";
      }
      // Lock released — IO-phase: work refresh + drain, no lock held.
      boost::asio::post(*m_context, [this, clean_best_changed]() {
        try {
            if (clean_best_changed) {
                LOG_INFO << "[CLEAN] IO-phase: work refresh (best changed)";
                // Same single fan-out every other tip-change leg uses: the
                // binding in main_dash.cpp calls dash::stratum::
                // fire_share_tip_refresh (bump -> notify_all -> dashboard).
                // No second notify call-site with its own logic.
                if (m_on_best_share_changed)
                    m_on_best_share_changed();
                broadcast_share(m_best_share_hash);  // re-announce new head
            }
            drain_pending_adds();
        } catch (const std::exception& e) {
            LOG_ERROR << "[CLEAN] IO phase failed: " << e.what();
        } catch (...) {
            LOG_ERROR << "[CLEAN] IO phase failed: unknown error";
        }
        // #854: the clean cycle holds the think slot too, so run_think()
        // requests that arrived during it (a mint, a peer best-advert) were
        // queued rather than dropped — serve them now.
        const bool rethink_owed =
            dash::think::release_think_slot(m_think_running, m_rethink_pending);
        m_clean_running.store(false);
        if (rethink_owed)
            boost::asio::post(*m_context, [this]() { run_think(); });
      });
    });
}

uint256 NodeImpl::best_share_hash()
{
    // The election walks verified.get_heads()/get_work() — chain-container
    // reads the compute thread's think() mutates (verified.add during the
    // bootstrap verify, chain.remove of bads) under the exclusive lock.
    // Callers here are the IO thread (work refresh, mint) AND the WebServer
    // HTTP thread (set_best_share_hash_fn / pool-hashrate fn), so an unlocked
    // walk races the rehash → the join-burst GP fault. Reader discipline
    // (m_tracker_mutex contract, node.hpp): shared_lock(try_to_lock), never
    // block; busy ⇒ the last published election (lock-free snapshot) — the
    // stable tip current jobs are already built on.
    // has_peers via the atomic mirror — m_peers itself is IO-thread-owned
    // and NOT covered by m_tracker_mutex, so touching the map here (HTTP /
    // compute thread) would race handle_version's insert (TSAN-captured).
    const bool has_peers = m_peer_count.load(std::memory_order_relaxed) > 0;
    if (is_compute_thread())    // exclusive lock already held
        return dash::mint::elect_best_share(m_tracker, m_best_share_hash,
                                            has_peers);
    std::shared_lock<std::shared_mutex> lock(m_tracker_mutex, std::try_to_lock);
    if (!lock.owns_lock())
        return snapshot_best_share();
    return dash::mint::elect_best_share(m_tracker, m_best_share_hash, has_peers);
}

void NodeImpl::broadcast_share(const uint256& share_hash)
{
    if (share_hash.IsNull())
        return;
    // try_to_lock: never block the IO thread on the compute thread's exclusive
    // lock — a deferred broadcast is picked up by the next think cycle.
    std::shared_lock<std::shared_mutex> lock(m_tracker_mutex, std::try_to_lock);
    if (!lock.owns_lock()) {
        static int defer_log = 0;
        if (defer_log++ % 50 == 0)
            LOG_INFO << "[broadcast_share] tracker busy — deferring "
                     << share_hash.GetHex().substr(0, 16);
        return;
    }

    if (!m_chain->contains(share_hash))
        return;

    // Walk back up to 5 shares, collecting the not-yet-broadcast ones. code
    // review F2: do NOT mark them shared here — the tx-completeness gate in
    // send_shares can skip a share for ALL peers (unbacked now, or zero peers),
    // and marking before the send would leave a skipped chain TIP permanently
    // "already shared" and never re-pushed → silent PPLNS-credit loss. We mark
    // only what actually reached >= 1 peer, below.
    std::vector<uint256> to_send;
    int32_t height = m_chain->get_height(share_hash);
    int32_t walk = std::min(height, 5);
    for (auto [hash, data] : m_chain->get_chain(share_hash, walk)) {
        if (m_shared_share_hashes.count(hash))
            break;
        to_send.push_back(hash);
    }
    if (to_send.empty())
        return;

    std::set<uint256> actually_sent;
    for (auto& [nonce, peer] : m_peers) {
        auto sent = send_shares(peer, to_send);
        actually_sent.insert(sent.begin(), sent.end());
    }
    // Mark ONLY shares that reached a peer; anything skipped for every peer (or
    // with no peers connected) stays un-marked and is retried on the next
    // broadcast — once its txs are retained or a peer appears.
    for (const auto& h : actually_sent)
        m_shared_share_hashes.insert(h);
}

std::vector<uint256> NodeImpl::send_shares(peer_ptr peer,
                                           const std::vector<uint256>& share_hashes)
{
    // Caller (broadcast_share) already holds a shared tracker lock; this
    // method only READS chain + m_known_txs and writes to the peer socket.
    // Returns the hashes of the shares actually SENT to this peer (F2): the
    // caller marks only those as broadcast, so a share skipped for all peers is
    // retried rather than silently withheld.
    std::vector<ShareType> shares;
    for (const auto& hash : share_hashes) {
        if (!m_chain->contains(hash))
            continue;
        for (auto [h, data] : m_chain->get_chain(hash, 1)) {
            shares.push_back(data.share);
            break;
        }
    }
    if (shares.empty())
        return {};

    // ── Tx-completeness gate (canonical p2pool p2p.py:404 parity) ───────────
    // A v13+ share references its new transactions by hash
    // (new_transaction_hashes); a canonical peer that cannot resolve those txs
    // DISCONNECTS us with "referenced unknown transaction" (p2p.py:403-404,
    // handle_shares / handle_remember_tx). We re-announce the best chain's head
    // and up to 5 ancestors (ROOT-2 re-announce, broadcast_share), and shares
    // pulled via sharereply arrive WITHOUT their txs (the reply carries no tx
    // bytes), so their tx bytes are absent from m_known_txs. Sending such a
    // share unbacked is exactly what makes the public canonical seeds drop the
    // connection ~300ms after handshake — the isolation root cause.
    //
    // So only broadcast a share when we HOLD the bytes of EVERY referenced new
    // tx (m_known_txs), so remember_tx below can always forward them. code
    // review F3: gating on m_remote_txs (the peer's have_tx advert) alone is
    // weaker than canonical — that advert can be stale (the peer may have dropped
    // the tx), and sending hash-only for a tx the peer no longer holds is exactly
    // the disconnect. Requiring the bytes is the canonical invariant
    // (sendShares broadcasts only txs in known_txs); m_remote_txs is used ONLY
    // below to choose hash-vs-bytes encoding. Skipping the rest costs no
    // propagation — a downloaded share is by definition already on the network we
    // fetched it from, and our own minted shares are backable by construction
    // (add_local_share declines a solve whose txs are not retained).
    {
        std::vector<ShareType> sendable;
        sendable.reserve(shares.size());
        size_t skipped_incomplete = 0;
        for (auto& share : shares) {
            bool backable = true;
            share.invoke([&](auto* obj) {
                backable = dash::all_txs_backable(obj->m_new_transaction_hashes,
                                                  m_known_txs);
            });
            if (backable)
                sendable.push_back(std::move(share));
            else
                ++skipped_incomplete;
        }
        if (skipped_incomplete > 0) {
            static int skip_log = 0;
            if (skip_log++ % 20 == 0)
                LOG_INFO << "[send_shares] skipped " << skipped_incomplete
                         << " share(s) whose new-tx bytes we do not hold "
                            "(downloaded via sharereply / template-evicted) to "
                         << peer->addr().to_string()
                         << " — avoids canonical 'unknown transaction' disconnect";
        }
        if (sendable.empty())
            return {};
        shares.swap(sendable);
    }

    // Forward the txs the peer needs BEFORE the shares (p2pool remember_tx
    // protocol) — a share referencing unknown txs makes the receiving oracle
    // node drop the connection.
    std::set<uint256> needed_txs;
    for (auto& share : shares) {
        share.invoke([&](auto* obj) {
            for (const auto& th : obj->m_new_transaction_hashes) {
                if (!peer->m_remote_txs.count(th) && !peer->m_remembered_txs.count(th))
                    needed_txs.insert(th);
            }
        });
    }
    if (!needed_txs.empty()) {
        std::vector<uint256> known_hashes;
        std::vector<coin::MutableTransaction> full_txs;
        size_t missing = 0;
        for (const auto& th : needed_txs) {
            if (peer->m_remote_txs.count(th)) {
                known_hashes.push_back(th);
            } else if (auto it = m_known_txs.find(th); it != m_known_txs.end()) {
                full_txs.emplace_back(it->second);
            } else {
                ++missing;
            }
        }
        if (missing > 0)
            LOG_WARNING << "[send_shares] " << missing << " referenced tx(s) not in "
                           "m_known_txs — peer may drop these shares "
                           "(register_template_txs gap?)";
        if (!known_hashes.empty() || !full_txs.empty()) {
            auto rtx_msg = message_remember_tx::make_raw(known_hashes, full_txs);
            peer->write(std::move(rtx_msg));
        }
    }

    // Pack and send via the message_shares wire codec (round-trip pinned by
    // the mint-runloop KATs, so a re-serialized share is byte-identical).
    std::vector<chain::RawShare> rshares;
    rshares.reserve(shares.size());
    for (auto& share : shares)
        rshares.emplace_back(share.version(), pack(share));
    auto shares_msg = message_shares::make_raw(rshares);
    peer->write(std::move(shares_msg));

    if (!needed_txs.empty()) {
        std::vector<uint256> forget_vec(needed_txs.begin(), needed_txs.end());
        auto ftx_msg = message_forget_tx::make_raw(forget_vec);
        peer->write(std::move(ftx_msg));
    }

    LOG_INFO << "[Pool] Sent " << shares.size() << " share(s) (+"
             << needed_txs.size() << " tx refs) to " << peer->addr().to_string();

    // F2: report exactly which shares reached this peer so the caller marks only
    // those broadcast (a share skipped for all peers stays un-marked → retried).
    std::vector<uint256> sent;
    sent.reserve(shares.size());
    for (auto& share : shares)
        sent.push_back(share.hash());
    return sent;
}

uint256 NodeImpl::add_local_share(ShareType share, bool block_winning)
{
    const uint256 hash = share.hash();
    if (hash.IsNull())
        return uint256::ZERO;

    {
        // Exclusive tracker lock.
        //
        // ORDINARY SHARE (block_winning == false) — UNCHANGED. Non-blocking
        // (architectural rule, node.hpp): if the compute thread is mid-think,
        // DECLINE the mint (fail-closed) — the miner keeps the pseudoshare
        // credit, the next solve mints. That trade is correct and stays exactly
        // as it was; tracker_acquire::exclusive() with Urgency::Opportunistic is
        // literally the same single `try_to_lock`.
        //
        // BLOCK-WINNING SHARE (#889) — BOUNDED WAIT. There is no next solve: the
        // block is found once, so a decline here permanently forfeits the
        // highest-work share this node will ever produce. Worse, it is not only
        // OUR share weight. p2pool nodes detect a pool block by watching for a
        // SHARE with pow_hash <= header bits target (p2pool/node.py:145-147), so
        // a block-winning share that never enters the sharechain is a block NO
        // peer — not even our own oracle — can ever record. A momentarily busy
        // tracker must not be allowed to do that.
        //
        // ⚠️ THE BLOCK IS ALREADY SUBMITTED BEFORE WE GET HERE. The won-block
        // arm in stratum/work_source.cpp dispatches the block via
        // submit_block_fn_ and only THEN calls the mint seam (#887/#888
        // ordering, with an ordering-witness KAT pinning it). So whatever this
        // wait costs, it can never delay, gate or endanger the block submit.
        //
        // #878/#881 GUARD: the compute thread already owns this mutex
        // exclusively, so it must never wait on it. is_compute_thread() degrades
        // the bounded path to a single try there. The live block-winning caller
        // (main_dash.cpp's mint lambda, reached from the stratum handler via
        // process_message -> handle_submit -> mining_submit) holds zero locks.
        const auto urgency = block_winning
            ? tracker_acquire::Urgency::BlockWinning
            : tracker_acquire::Urgency::Opportunistic;
        auto lock = tracker_acquire::exclusive(m_tracker_mutex, urgency,
                                               is_compute_thread());
        if (!lock.owns_lock()) {
            if (block_winning) {
                // LOUD + COUNTED. A silent drop is precisely the defect; this
                // is the only remaining way a won block can go unseen, and it
                // must be impossible to miss in a log or a dashboard.
                m_block_share_lock_forfeits.fetch_add(1, std::memory_order_relaxed);
                LOG_ERROR << "[MINT-BLOCK] FORFEIT — tracker still busy after "
                          << tracker_acquire::BLOCK_SHARE_LOCK_BUDGET.count()
                          << "ms; BLOCK-WINNING share "
                          << hash.GetHex().substr(0, 16)
                          << " NOT minted. The block itself was already "
                             "submitted, but no p2pool peer will see it and its "
                             "PPLNS weight is lost. forfeits="
                          << m_block_share_lock_forfeits.load(std::memory_order_relaxed);
            } else {
                LOG_WARNING << "[MINT] tracker busy — local share "
                            << hash.GetHex().substr(0, 16) << " declined (retry on next solve)";
            }
            return uint256::ZERO;
        }
        if (m_chain->contains(hash)) {
            LOG_WARNING << "[MINT] duplicate local share " << hash.GetHex().substr(0, 16);
            return uint256::ZERO;
        }

        // F1-sub (by-construction backability): DECLINE a solve whose template
        // txs are no longer retained in m_known_txs, rather than mint a share
        // send_shares would then have to withhold. FrozenJobRegistry
        // (mint_runloop.hpp) is a FIFO cap-512 with NO TTL and re-put refreshes,
        // so a solve can arrive from an arbitrarily-old job — no finite retention
        // window is a provable bound, so the only by-construction guarantee is to
        // fail closed here: every share we add is fully forwardable. The miner
        // keeps the pseudoshare credit; the next solve on a fresh job mints. The
        // deduped rolling template window (register_template_txs) keeps declines
        // rare — this fires only for genuinely stale solves past the window.
        {
            bool backable = true;
            share.invoke([&](auto* obj) {
                backable = dash::all_txs_backable(obj->m_new_transaction_hashes,
                                                  m_known_txs);
            });
            if (!backable) {
                // #889 scope note: this decline is NOT the lock hazard and is
                // deliberately NOT bypassed for a block-winning share — minting
                // a share whose txs we cannot serve would produce a share
                // send_shares must withhold, i.e. the same invisibility by a
                // different route. It is escalated to LOG_ERROR on the block
                // path only so the loss is never quiet.
                if (block_winning) {
                    LOG_ERROR << "[MINT-BLOCK] BLOCK-WINNING share "
                              << hash.GetHex().substr(0, 16)
                              << " references template tx(s) no longer retained "
                                 "— NOT minted (stale job past the retention "
                                 "window). The block itself was already "
                                 "submitted; this is a separate, non-lock "
                                 "forfeit — see register_template_txs retention.";
                } else {
                    LOG_WARNING << "[MINT] local share " << hash.GetHex().substr(0, 16)
                                << " references template tx(s) no longer retained — "
                                   "declined (stale job past retention window; retry "
                                   "on next solve)";
                }
                return uint256::ZERO;
            }
        }

        m_tracker.add(share);
        // Local share: verify inline (p2pool: set_best_share → think verifies;
        // the inline attempt keeps the just-mint tip usable immediately).
        m_tracker.attempt_verify(hash);

        if (m_storage && m_storage->is_available()) {
            std::vector<c2pool::storage::SharechainStorage::ShareBatchEntry> db_batch;
            collect_share_batch_entry(share, db_batch);
            m_storage->store_shares_batch(db_batch);
        }
    }

    // Lock released — relay + rescore (both take their own locks / post).
    // #854: this run_think() is the ONLY thing that promotes the share we just
    // minted to the tip and thereby pushes fresh work to the rigs. It used to
    // be dropped outright whenever it landed during a think/clean IO-phase
    // (IO thread, tracker lock already released, m_think_running still true) —
    // the residual missed-notify path. acquire_think_slot() now queues it.
    broadcast_share(hash);
    run_think();
    return hash;
}

// #950: standing remembered-set seed (canonical p2p.py:269). Declared in
// node.hpp. IO-thread only. Sizes each tx with canonical's 100 + packed_size
// accounting (p2p.py:379) so the seed never overshoots the peer's cap (p2p.py:488).
static std::size_t remembered_tx_size(const coin::Transaction& tx)
{
    coin::MutableTransaction mtx(tx);
    return 100 + pack(coin::TX_WITH_WITNESS(mtx)).get_span().size();
}

void NodeImpl::send_standing_remember(const peer_ptr& peer)
{
    if (!peer)
        return;
    std::vector<coin::MutableTransaction> full_txs;
    {
        // try_to_lock, never block: mirrors advertise_known_txs — if the compute
        // thread is mid-cycle we skip; the next inbound handshake reseeds.
        std::shared_lock<std::shared_mutex> lk(m_tracker_mutex, std::try_to_lock);
        if (!lk.owns_lock())
            return;
        auto chosen = dash::select_standing_remember(
            m_known_txs, MAX_REMEMBERED_TXS_SIZE, &remembered_tx_size);
        full_txs.reserve(chosen.size());
        for (const auto& h : chosen)
            if (auto it = m_known_txs.find(h); it != m_known_txs.end())
                full_txs.emplace_back(it->second);
    }
    if (full_txs.empty())
        return;
    // Canonical p2p.py:269 sends tx_hashes=[] (all as bodies): at handshake we do
    // not yet know the peer's remote_tx_hashes.
    peer->write(dash::message_remember_tx::make_raw({}, full_txs));
}

void NodeImpl::register_template_txs(const std::vector<coin::Transaction>& txs,
                                     const std::vector<uint256>& hashes)
{
    // THREAD-CONFINEMENT (enforced, not assumed): every m_known_txs mutator in
    // this lane must run OFF the compute thread — the two remember_tx ingests
    // (protocol_actual.cpp:263 / protocol_legacy.cpp:299) are IO-thread by
    // construction, and so is this one (producer-job cache miss on the stratum
    // path). advertise_known_txs() reads the map from the IO thread on exactly
    // that basis. A compute-thread caller here would turn that read into a
    // genuine data race, so trip loudly in debug builds rather than let it be
    // discovered in production.
    assert(!is_compute_thread() &&
           "register_template_txs must not run on the compute thread — "
           "m_known_txs is IO-thread-confined (see advertise_known_txs)");

    if (txs.size() != hashes.size()) {
        LOG_WARNING << "[register_template_txs] size mismatch txs=" << txs.size()
                    << " hashes=" << hashes.size() << " — skipped";
        return;
    }
    // Retain a rolling window of the last RETAINED_TEMPLATE_TX_SETS DISTINCT
    // templates; a tx leaves m_known_txs only once it has fallen out of EVERY
    // retained set — so a share minted on any recent job (the miner may solve a
    // job whose template has since rotated) and a ROOT-2 re-announce a few
    // rotations later can still forward the referenced tx bytes via remember_tx.
    //
    // code review F1: register_template_txs is called per producer-job cache
    // MISS = per (prev_share_hash, payout_script) (main_dash.cpp:1539, key
    // :1450), NOT per template rotation. A ~50-payout-script cluster re-registers
    // the SAME template ~50 times on one tip, so pushing each unconditionally
    // would collapse the window to a single template. retain_template_txs()
    // dedups by TEMPLATE IDENTITY (the tx-hash set): a set already retained just
    // refreshes recency and consumes no slot, so the window holds N DISTINCT
    // templates (≈ minutes of stale-solve coverage), not N re-registrations.
    dash::retain_template_txs(m_recent_template_tx_sets, m_known_txs,
                              hashes, txs, RETAINED_TEMPLATE_TX_SETS);
}

} // namespace dash