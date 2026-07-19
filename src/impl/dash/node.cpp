// SPDX-License-Identifier: AGPL-3.0-or-later
#include "node.hpp"
#include "share.hpp"
#include "mint_runloop.hpp"   // dash::mint::elect_best_share (election policy SSOT)

#include <core/uint256.hpp>
#include <core/common.hpp>

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
                continue;

            if (m_chain->contains(share.hash()))
            {
                ++dup_count;
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
    flush_verified_to_leveldb();
    if (!m_removal_flush_buf.empty() && m_storage && m_storage->is_available()) {
        m_storage->remove_shares_batch(m_removal_flush_buf);
        m_removal_flush_buf.clear();
    }
}

void NodeImpl::run_think()
{
    // Serialize: only one think() in flight (compute pool has 1 thread).
    if (m_think_running.exchange(true)) {
        static int skip_log = 0;
        if (skip_log++ % 20 == 0)
            LOG_INFO << "[ASYNC-THINK] skipped — compute thread busy";
        return;
    }
    if (!m_context) {
        // Rig-free (KAT/standalone) node: no IO context to hop back to.
        m_think_running.store(false);
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
            // Peers that fed unverifiable shares: LOG ONLY for now — the DASH
            // node carries no ban list yet (honest gap; the reception slice's
            // error() close still applies to protocol violations).
            for (const auto& bad_addr : result.bad_peer_addresses)
                LOG_WARNING << "[think] peer provided unverifiable shares: "
                            << bad_addr.to_string();

            // Desired-share download (p2pool node.py download loop) is NOT yet
            // ported to the DASH node — log the gap loudly instead of silently
            // dropping it. Reception can still serve peers (handle_get_share);
            // filling OUR gaps from peers rides the download slice.
            if (!result.desired.empty()) {
                static int desired_log = 0;
                if (desired_log++ % 20 == 0)
                    LOG_WARNING << "[think] " << result.desired.size()
                                << " desired share(s) not requested — the DASH "
                                   "share-download leg is a later slice";
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

            m_think_running.store(false);

            if (needs_continue)
                boost::asio::post(*m_context, [this]() { run_think(); });
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

uint256 NodeImpl::best_share_hash()
{
    return dash::mint::elect_best_share(m_tracker, m_best_share_hash, !m_peers.empty());
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

    // Walk back up to 5 shares, collecting the not-yet-broadcast ones.
    std::vector<uint256> to_send;
    int32_t height = m_chain->get_height(share_hash);
    int32_t walk = std::min(height, 5);
    for (auto [hash, data] : m_chain->get_chain(share_hash, walk)) {
        if (m_shared_share_hashes.count(hash))
            break;
        m_shared_share_hashes.insert(hash);
        to_send.push_back(hash);
    }
    if (to_send.empty())
        return;

    for (auto& [nonce, peer] : m_peers)
        send_shares(peer, to_send);
}

void NodeImpl::send_shares(peer_ptr peer, const std::vector<uint256>& share_hashes)
{
    // Caller (broadcast_share) already holds a shared tracker lock; this
    // method only READS chain + m_known_txs and writes to the peer socket.
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
        return;

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
}

uint256 NodeImpl::add_local_share(ShareType share)
{
    const uint256 hash = share.hash();
    if (hash.IsNull())
        return uint256::ZERO;

    {
        // Exclusive tracker lock, non-blocking (architectural rule): if the
        // compute thread is mid-think, DECLINE the mint (fail-closed) — the
        // miner keeps the pseudoshare credit, the next solve mints.
        std::unique_lock lock(m_tracker_mutex, std::try_to_lock);
        if (!lock.owns_lock()) {
            LOG_WARNING << "[MINT] tracker busy — local share "
                        << hash.GetHex().substr(0, 16) << " declined (retry on next solve)";
            return uint256::ZERO;
        }
        if (m_chain->contains(hash)) {
            LOG_WARNING << "[MINT] duplicate local share " << hash.GetHex().substr(0, 16);
            return uint256::ZERO;
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
    broadcast_share(hash);
    run_think();
    return hash;
}

void NodeImpl::register_template_txs(const std::vector<coin::Transaction>& txs,
                                     const std::vector<uint256>& hashes)
{
    if (txs.size() != hashes.size()) {
        LOG_WARNING << "[register_template_txs] size mismatch txs=" << txs.size()
                    << " hashes=" << hashes.size() << " — skipped";
        return;
    }
    // Drop the PREVIOUS template's leftovers that the new template no longer
    // carries, then insert the new set — m_known_txs stays bounded by one
    // template (plus reception-protocol remembered txs, which are peer-scoped).
    std::set<uint256> new_set(hashes.begin(), hashes.end());
    for (const auto& old_hash : m_template_tx_hashes) {
        if (!new_set.count(old_hash))
            m_known_txs.erase(old_hash);
    }
    for (size_t i = 0; i < txs.size(); ++i)
        m_known_txs.insert_or_assign(hashes[i], txs[i]);
    m_template_tx_hashes = std::move(new_set);
}

} // namespace dash