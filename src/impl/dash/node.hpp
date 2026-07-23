// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// Dash p2pool sharechain pool-node — S8 pool-node leaf 5 (FINAL), slice A.
//
// SLICE A SCOPE: class skeleton + accessors + KAT ONLY. This is one slice of a
// 4-slice plan (A=skeleton+accessors+KAT, B=reception, C=broadcast/persist,
// D=think-loop). Reception (message handlers / Legacy / Actual / NodeBridge),
// broadcast/persist, and the think() compute-loop bodies are DEFERRED to the
// later slices and are intentionally NOT declared here.
//
// Namespace-ported from the btc::NodeImpl prod reference (src/impl/btc/node.hpp),
// reconciled against DASH's actual headers (dash::Config, dash::ShareChain,
// dash::ShareTracker, dash::Peer, dash::coin::Transaction). DASH is X11 but the
// pool-node layer is consensus-agnostic; the slice-A surface (lifecycle fields,
// async-compute pipeline scaffold, lock-free snapshot, tracker accessors) is
// byte-for-byte the same shape as btc/dgb.

#include "config.hpp"
#include "share.hpp"
#include "share_chain.hpp"
#include "share_tracker.hpp"
#include "peer.hpp"
#include "min_protocol_gate.hpp"
#include "auto_ratchet.hpp"          // dash::apply_min_protocol_ratchet_decision (v36 accept-floor ratchet)
#include "version_negotiation.hpp"   // dash::version_negotiation::get_desired_version_weights (ratchet window)
#include "messages.hpp"
#include "coin/transaction.hpp"
#include "coin/node_coin_state.hpp"       // dash::coin::NodeCoinState (node-held embedded bundle)
#include "coin/coin_state_maintainer.hpp" // dash::coin::CoinStateMaintainer (reception/think driver)

#include <pool/node.hpp>
#include <pool/protocol.hpp>
#include <pool/share_download.hpp>  // shared downloader helpers (#754)
#include <core/reply_matcher.hpp>
#include <c2pool/storage/sharechain_storage.hpp>

#include <boost/asio/thread_pool.hpp>
#include <boost/asio/steady_timer.hpp>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <random>
#include <set>
#include <shared_mutex>
#include <string>
#include <thread>
#include <vector>

namespace dash
{

// Batch of received shares (+ their raw bytes and needed txs) awaiting tracker
// insertion. Slice A defines the complete shell so m_pending_adds's
// unique_ptr<HandleSharesData> has a complete type at destruction; the reception
// slice (B) drives add()/drain. Mirrors btc::HandleSharesData.
struct HandleSharesData
{
    std::vector<ShareType> m_items;
    std::vector<chain::RawShare> m_raw_items; // original raw bytes, parallel with m_items
    std::map<uint256, std::vector<coin::MutableTransaction>> m_txs;

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
};

// Response payload delivered to a pending async share request when a sharereply
// arrives. Parsed shares plus their original raw payloads (so relay re-sends the
// exact bytes received). Wired into the reply_matcher typedef below.
struct ShareReplyData
{
    std::vector<ShareType> m_items;
    std::vector<chain::RawShare> m_raw_items;
};

class NodeImpl : public pool::BaseNode<dash::Config, dash::ShareChain, dash::Peer>
{
    // Async share downloader:
    //   ID       = uint256 (matches sharereq id to sharereply id)
    //   RESPONSE = parsed shares plus their original raw payloads
    //   REQUEST  = req_id, peer, hashes, parents, stops
    using share_getter_t = ReplyMatcher::ID<uint256>
        ::RESPONSE<dash::ShareReplyData>
        ::REQUEST<uint256, peer_ptr, std::vector<uint256>, uint64_t, std::vector<uint256>>;

protected:
    share_getter_t m_share_getter;
    ShareTracker m_tracker;
    std::unique_ptr<c2pool::storage::SharechainStorage> m_storage;

    // Global pool of known transactions, populated by remember_tx and the coin
    // daemon. Reception-slice protocol handlers look up tx hashes here.
    std::map<uint256, coin::Transaction> m_known_txs;

    // Embedded coin-state (S8 embedded_gbt live-wire capstone). The node-held
    // bundle build_embedded_workdata() consumes (MN list + mempool + tip
    // params) plus the maintainer that keeps it current off the async
    // reception/think update path. Until the maintainer publishes (both a
    // non-empty MN list AND a tip have arrived), populated() stays false and
    // select_work() routes to the RETAINED dashd getblocktemplate fallback --
    // the always-reachable safety path + [GBT-XCHECK] cross-check, never
    // removed. Declaration order matters: the maintainer holds a reference to
    // m_coin_state, so the bundle must be declared first.
    coin::NodeCoinState       m_coin_state;
    coin::CoinStateMaintainer m_coin_state_maintainer{m_coin_state};

    // Wire-message parser used by the Legacy/Actual dispatch protocols to turn
    // a RawMessage into a typed message variant. Mirrors dgb::NodeImpl::m_handler.
    dash::Handler m_handler;

    // Callback fired when a bestblock message is received from a peer; wired by
    // the work layer (slice .4) to trigger a work refresh. Mirrors dgb.
    std::function<void(const uint256&)> m_on_bestblock;

    // Thread pool for parallel share_init_verify (X11 CPU work). Keeps the
    // expensive crypto off the io_context thread.
    boost::asio::thread_pool m_verify_pool{4};

    // ── Async compute pipeline ──────────────────────────────────────────
    // think() (slice D) runs on m_think_pool (1 thread) holding m_tracker_mutex
    // exclusively. The IO thread NEVER calls lock() — only try_to_lock(). If the
    // mutex is held by the compute thread, the IO thread defers the operation and
    // continues processing network I/O. Synchronization contract:
    //   Compute thread:   unique_lock(m_tracker_mutex)  — exclusive, blocking
    //   IO thread reads:  shared_lock(try_to_lock)      — non-blocking, skip if busy
    //   IO thread writes: unique_lock(try_to_lock)      — non-blocking, queue if busy
    boost::asio::thread_pool m_think_pool{1};
    std::atomic<bool> m_think_running{false};
    std::atomic<bool> m_clean_running{false};
    mutable std::shared_mutex m_tracker_mutex;

    // ── Lock-free stats snapshot ─────────────────────────────────────────
    // Published by think() on the compute thread under m_tracker_mutex. Read by
    // ALL consumers (sync_status, loading page, global_stats, graph data, …)
    // WITHOUT needing the tracker lock — the c2pool equivalent of p2pool's
    // reactor-thread stats variables.
    struct TrackerSnapshot {
        int chain_count{0};
        int verified_count{0};
        int head_count{0};
        int orphan_shares{0};
        int dead_shares{0};
        int fork_count{0};
        double pool_hashrate{0};
    };
    void publish_snapshot() {
        TrackerSnapshot s;
        s.chain_count = static_cast<int>(m_tracker.chain.size());
        s.verified_count = static_cast<int>(m_tracker.verified.size());
        s.head_count = static_cast<int>(m_tracker.chain.get_heads().size());
        s.fork_count = s.head_count;
        std::lock_guard<std::mutex> lock(m_snapshot_mutex);
        m_snapshot = s;
    }
    mutable std::mutex m_snapshot_mutex;
    TrackerSnapshot m_snapshot;

    // Identity of the compute thread (m_think_pool's single thread). Used by
    // TrackerReadGuard to skip shared_lock when the caller is already on the
    // compute thread (which holds the exclusive lock).
    std::atomic<std::thread::id> m_compute_thread_id{};

    // Pending share batches queued while think() holds the mutex; drained on the
    // IO thread after think() releases the lock. unique_ptr because
    // HandleSharesData is forward-declared here (defined in the reception slice).
    struct PendingShareBatch {
        std::unique_ptr<HandleSharesData> data;
        NetService addr;
    };
    std::vector<PendingShareBatch> m_pending_adds;

    // ── think() watchdog + backpressure (livelock defense-in-depth) ──
    // If a think() cycle exceeds THINK_WATCHDOG_SECONDS the watchdog (slice D)
    // logs compute-thread state, flags the cycle, and resets m_think_running so
    // the pipeline recovers instead of wedging. The watchdog NEVER touches
    // m_tracker_mutex. MAX_PENDING_ADDS caps the deferred queue.
    static constexpr int THINK_WATCHDOG_SECONDS = 30;
    static constexpr size_t MAX_PENDING_ADDS = 256;
    std::atomic<int64_t> m_think_deadline_ns{0};
    std::atomic<uint64_t> m_think_generation{0};
    std::unique_ptr<boost::asio::steady_timer> m_watchdog_timer;

    // Top-5 scored heads from last think() — used by clean_tracker() (slice D)
    // to protect the best chains from head pruning.
    std::vector<uint256> m_last_top5_heads;

    // Buffer of newly verified share hashes, flushed to LevelDB periodically.
    std::vector<uint256> m_verified_flush_buf;
    // Buffer of pruned share hashes, batch-deleted from LevelDB after clean.
    std::vector<uint256> m_removal_flush_buf;

    // ── Run-loop mint slice (3/3) state ─────────────────────────────────
    // Best-share election result — published by run_think() on the compute
    // thread under m_tracker_mutex (mirrors btc::NodeImpl::m_best_share_hash).
    uint256 m_best_share_hash;

    // ── v36 min-protocol accept-floor ratchet (#643/#646, mirrors dgb) ──────────
    // Runtime P2P accept-floor, seeded from the COLD config floor (1700, accept-all)
    // and lifted to NEW_MINIMUM_PROTOCOL_VERSION (3600) by apply_min_protocol_ratchet()
    // once the work-weighted desired-version tally over the [9/10..10/10] window behind
    // the best share holds >= 95% for v36. Mutated ONLY on the compute thread under the
    // exclusive m_tracker_mutex (same sites as m_best_share_hash); it drives the LIVE
    // m_min_protocol_gate.min_version so the handshake reception reflects the ratchet.
    std::atomic<uint32_t> m_runtime_min_protocol_version{
        SharechainConfig::MINIMUM_PROTOCOL_VERSION};

    // De-dup set for broadcast_share (hashes already relayed to peers).
    std::set<uint256> m_shared_share_hashes;
    // Hashes of the CURRENT template's txs registered in m_known_txs by
    // register_template_txs — replaced wholesale each registration so the
    // known-tx pool stays bounded by one template.
    std::set<uint256> m_template_tx_hashes;
    // Fired on the IO thread when run_think() elects a new best share
    // (p2pool: new_work_event) — main_dash binds the stratum work refresh.
    std::function<void()> m_on_best_share_changed;
    // Chain-relative block height for think() scoring; unbound -> zero fn.
    std::function<int32_t(uint256)> m_block_rel_height_fn;

    // ── Share-download leg (#754) state — IO-thread only ────────────────
    // De-dup + per-cycle retry gate for in-flight sharereq targets (shared
    // pool/share_download.hpp; ltc m_downloading_shares/m_download_fail_count).
    pool::download::DownloadGate m_download_gate;
    // req_id → peer addr for selective cancellation on disconnect. p2pool has
    // per-peer get_shares deferrers (connectionLost → respond_all on just that
    // peer); c2pool's m_share_getter is shared, so the ownership is tracked
    // here (ltc node.hpp:511 parity).
    std::map<uint256, NetService> m_pending_share_reqs;
    // Best-share adverts learned in handle_version, awaiting download. The
    // inline (vtable) handle_version body must stay link-free for the
    // rig-free KAT targets (they build NodeImpl WITHOUT the node.cpp TU), so
    // it QUEUES here; run_think()'s IO phase + the advert timer started by
    // start_outbound_connections() (both node.cpp) drain the queue into
    // download_shares — the oracle p2p.py handle_version →
    // node.handle_share_hashes join trigger, one hop later.
    std::vector<std::pair<std::weak_ptr<peer_t>, uint256>> m_peer_best_adverts;

    // ── Outbound dialing (btc/ltc start_outbound_connections port) ──────
    static constexpr size_t DEFAULT_TARGET_OUTBOUND_PEERS = 8;
    size_t m_max_peers = 30;
    size_t m_target_outbound_peers = DEFAULT_TARGET_OUTBOUND_PEERS;
    std::unique_ptr<core::Timer> m_connect_timer;   // 30s dial maintenance
    std::unique_ptr<core::Timer> m_advert_timer;    // 2s best-advert drain
    std::set<NetService> m_pending_outbound;  // addresses currently being dialed
    std::set<NetService> m_outbound_addrs;    // established outbound peers

    // ── P2P ban list (btc node.hpp:533-545 port) ────────────────────────
    // Peers that fed unverifiable shares (think()'s bad_peer_addresses) are
    // banned for m_ban_duration; expired entries are swept each think cycle.
    std::map<NetService, std::chrono::steady_clock::time_point> m_ban_list;
    std::chrono::seconds m_ban_duration{300};   // 5 minutes (configurable)
    std::map<std::string, std::chrono::steady_clock::time_point> m_ip_ban_list;
    // Whitelist: permanent dial targets (--addnode/--connect bootstrap seeds)
    // are immune to bans — banning the only seed of a small mesh would lock
    // the node out of its own pool (btc is_banned whitelist-bypass parity;
    // populated from the config bootstrap list in the ctor).
    std::set<std::string> m_whitelist_ips;
    std::set<NetService> m_whitelist_hosts;

public:
    // Default (rig-free) construction for tests/standalone: no io_context, the
    // share-getter requester is a no-op (there are no peers to write a
    // sharereq to; the ctx ctor below wires the real writer). Routes m_chain
    // at the tracker's main chain so any BaseNode path that reads m_chain is
    // valid.
    NodeImpl()
        : m_share_getter(nullptr,
            [](uint256, peer_ptr, std::vector<uint256>, uint64_t, std::vector<uint256>){})
    {
        m_chain = &m_tracker.chain;
        std::mt19937_64 rng(std::random_device{}());
        m_nonce = rng();
    }

    NodeImpl(boost::asio::io_context* ctx, config_t* config)
        : base_t(ctx, config),
          // #754 share-download leg: the REAL sharereq writer (ltc
          // node.hpp:162-170 parity) — packs the request through the
          // message_sharereq wire codec and writes it to the chosen peer.
          m_share_getter(ctx,
            [](uint256 req_id, peer_ptr to_peer,
               std::vector<uint256> hashes, uint64_t parents,
               std::vector<uint256> stops)
            {
                auto rmsg = dash::message_sharereq::make_raw(
                    req_id, hashes, parents, stops);
                to_peer->write(std::move(rmsg));
            },
            15)  // p2pool p2p.py:80 — 15s timeout for share requests
    {
        // Seed addr store with hardcoded bootstrap peers.
        m_addrs.load(config->pool()->m_bootstrap_addrs);
        // Bootstrap seeds are whitelisted: permanent dial targets are immune
        // to bans (btc is_banned whitelist-bypass parity).
        for (const auto& seed : config->pool()->m_bootstrap_addrs) {
            m_whitelist_ips.insert(seed.address());
            m_whitelist_hosts.insert(seed);
        }
        // Randomise our nonce so we detect self-connections.
        std::mt19937_64 rng(std::random_device{}());
        m_nonce = rng();
        // Route m_chain (used by BaseNode) at the tracker's main chain.
        m_chain = &m_tracker.chain;
    }

    // INetwork: a pool node does not initiate disconnect; the reception slice
    // overrides connected(). Slice A only needs disconnect() to satisfy the
    // pure-virtual INetwork contract.
    void disconnect() override { }

    // ICommunicator: the message-dispatch entry point. Slice B wires the real
    // version-handshake routing so handle_version() (and its live #646 gate) is
    // actually reachable -- mirrors the pool::NodeBridge unknown-peer branch
    // (src/pool/node.hpp). Full Legacy/Actual established-peer message dispatch
    // (shares, txs, getaddrs) rides a later slice; until then, post-handshake
    // messages are dropped. The handshake + min-protocol discrimination is live.
    void handle(std::unique_ptr<RawMessage> rmsg, const NetService& service) override
    {
        // Guard: the peer may have been removed by a prior error/timeout while an
        // async_read callback was still in-flight for the same socket.
        if (!m_connections.contains(service))
            return;
        auto peer = m_connections[service];
        peer->m_timeout->restart();

        if (peer->type() == pool::PeerConnectionType::unknown)
        {
            // The first message from an unknown peer MUST be `version`.
            if (rmsg->m_command.compare(0, 7, "version") != 0)
                return error("expected version message", service);

            std::optional<pool::PeerConnectionType> peer_type;
            try {
                peer_type = handle_version(std::move(rmsg), peer);
            } catch (const std::exception& ex) {
                error(ex.what(), service);
                return;
            }
            if (!peer_type.has_value()) {
                // self- or duplicate-connection: graceful close.
                close_connection(service);
                return;
            }
            peer->stable(*peer_type, PEER_TIMEOUT_TIME);
            return;
        }

        // Established peer: full Legacy/Actual message dispatch rides a later
        // slice; post-handshake messages are dropped for now.
    }

    // Keep-alive ping (reception's ping handler is live; the sender keeps the
    // peer's timeout timer from firing on the remote side).
    void send_ping(peer_ptr peer) override
    {
        auto rmsg = dash::message_ping::make_raw();
        peer->write(std::move(rmsg));
    }

    // Run-loop mint slice (3/3): SEND our version on every new connection —
    // without it a p2pool-dash peer times out waiting for our handshake and
    // drops the link (reception alone cannot hold a session). Advertises
    // advertised_best_share() so peers pull our chain (btc ROOT-2 parity).
    // INLINE (not node.cpp): connected() is virtual, so its body must be
    // visible to every TU that emits the NodeImpl vtable — the link-deferred
    // KAT targets instantiate NodeImpl without the node.cpp TU.
    // ── P2P ban check (btc node.cpp:2183-2196 port, inline for the vtable-
    // complete KAT targets). Whitelisted permanent dial targets bypass bans.
    bool is_whitelisted(const NetService& addr) const
    {
        return m_whitelist_ips.contains(addr.address())
            || m_whitelist_hosts.contains(addr);
    }
    bool is_banned(const NetService& addr) const
    {
        if (is_whitelisted(addr)) return false;
        const auto now = std::chrono::steady_clock::now();
        auto it = m_ban_list.find(addr);
        if (it != m_ban_list.end() && it->second > now) return true;
        auto ip_it = m_ip_ban_list.find(addr.address());
        if (ip_it != m_ip_ban_list.end() && ip_it->second > now) return true;
        return false;
    }
    void set_ban_duration(int seconds) { m_ban_duration = std::chrono::seconds(seconds); }

    void connected(std::shared_ptr<core::Socket> socket) override
    {
        // Reject banned peers (btc node.cpp:133-139).
        if (is_banned(socket->get_addr()))
        {
            LOG_INFO << "[Pool] Rejecting connection from banned peer "
                     << socket->get_addr().to_string();
            socket->close();
            return;
        }

        // Outbound lifecycle tracking (#754, ltc node.cpp:128-149): a dial we
        // initiated graduates from pending to established.
        const bool is_outbound = m_pending_outbound.erase(socket->get_addr()) > 0;

        // BaseNode creates the peer + timeout timer; then OPEN the handshake.
        // p2pool sends version from both sides on connectionMade — a silent
        // side gets dropped by the remote's handshake timeout.
        base_t::connected(socket);
        auto it = m_connections.find(socket->get_addr());
        if (it != m_connections.end())
        {
            if (is_outbound)
                m_outbound_addrs.insert(socket->get_addr());
            send_version(it->second);
        }
    }

    // ── Disconnect cleanup (#754, ltc node.cpp:151-241 reduced) ─────────
    // Cancel this peer's pending share requests (invokes their callbacks with
    // an empty reply so the download gate releases the hashes immediately
    // instead of waiting out the 15s ReplyMatcher timeout — p2pool p2p.py:595
    // get_shares.respond_all on connectionLost), drop its stale nonce entry
    // from m_peers (without this, reconnects are rejected as false
    // duplicates), and clear the outbound tracking. INLINE (vtable bodies must
    // stay link-free for the rig-free KAT targets).
    using base_t::error;   // keep the error_code overload visible
    void error(const message_error_type& err, const NetService& service,
               const std::source_location where =
                   std::source_location::current()) override
    {
        cancel_peer_share_requests(service);
        for (auto it = m_peers.begin(); it != m_peers.end(); )
        {
            if (it->second && it->second->addr() == service)
                it = m_peers.erase(it);
            else
                ++it;
        }
        m_pending_outbound.erase(service);
        m_outbound_addrs.erase(service);
        base_t::error(err, service, where);
    }

    void close_connection(const NetService& service) override
    {
        cancel_peer_share_requests(service);
        m_pending_outbound.erase(service);
        m_outbound_addrs.erase(service);
        base_t::close_connection(service);
    }

    void cancel_peer_share_requests(const NetService& service)
    {
        std::vector<uint256> to_cancel;
        for (const auto& [req_id, peer_addr] : m_pending_share_reqs)
        {
            if (peer_addr == service)
                to_cancel.push_back(req_id);
        }
        for (const auto& req_id : to_cancel)
        {
            m_pending_share_reqs.erase(req_id);
            m_share_getter.cancel(req_id);  // fires callback with empty reply
        }
    }

    void send_version(peer_ptr peer)
    {
        auto rmsg = dash::message_version::make_raw(
            SharechainConfig::ADVERTISED_PROTOCOL_VERSION,  // advertise v36 capability (3600); >= ratchet target so ratcheted peers accept us. Legacy peers (floor 1700) accept any >=1700, so backward-compatible.
            1,                                           // services
            addr_t{1, peer->addr()},                     // addr_to (the remote)
            addr_t{1, NetService{"0.0.0.0", SharechainConfig::p2p_port()}},  // addr_from
            m_nonce,
            std::string("c2pool"),
            1,                                           // mode (always 1, legacy compat)
            advertised_best_share());                    // head advert (raw pre-sync)
        peer->write(std::move(rmsg));
    }

    /// Head advertised to peers: think()'s best when known, else the tallest
    /// RAW chain head (btc ROOT-2: a pre-sync/genesis node must still let a
    /// connecting peer learn it HAS a chain and pull it). Inline — reachable
    /// from send_version() above.
    uint256 advertised_best_share()
    {
        if (!m_best_share_hash.IsNull())
            return m_best_share_hash;
        uint256 best;
        int32_t best_height = -1;
        for (const auto& [head_hash, tail_hash] : m_tracker.chain.get_heads()) {
            const auto h = static_cast<int32_t>(m_tracker.chain.get_height(head_hash));
            if (h > best_height) {
                best = head_hash;
                best_height = h;
            }
        }
        return best;
    }

    // #646 min-protocol ratchet gate -- LIVE per-instance floor. Default-
    // constructed it holds the oracle accept-all floor (1700), so at the default
    // this gate is a no-op; the operator lifts min_version at G2-migration time
    // and this reception then rejects any peer advertising a sub-floor protocol.
    dash::MinProtocolGate m_min_protocol_gate;

    // Slice B: real version-handshake reception. Mirrors the ltc::NodeImpl
    // reference (src/impl/ltc/node.cpp:265) reconciled to DASH's header-only
    // node and message set. Parses message_version, guards self- and duplicate
    // connections, fires the #646 min-protocol discrimination, registers the
    // peer, and returns the negotiated connection type. The share-download /
    // getaddrs machinery LTC drives here is not yet present on the DASH node and
    // rides a later slice; this reception is what flips G2 dual-pool from a
    // dormant seam to a live cross-peer.
    std::optional<pool::PeerConnectionType>
    handle_version(std::unique_ptr<RawMessage> rmsg, peer_ptr peer) override
    {
        auto msg = dash::message_version::make(rmsg->m_data);

        if (peer->m_other_version.has_value())
            throw std::runtime_error("more than one version message");

        peer->m_other_version = msg->m_version;
        peer->m_other_subversion = msg->m_subversion;

        // Self-connection guard: we dialled our own advertised nonce.
        if (m_nonce == msg->m_nonce)
            return std::nullopt;

        // Duplicate-connection guard: already peered with this nonce.
        if (m_peers.contains(msg->m_nonce))
            return std::nullopt;

        // #646 min-protocol ratchet -- LIVE discrimination. Throwing here makes
        // the NodeBridge close the connection (pool/node.hpp handle()). The
        // effective floor is the MAX of the operator knob (m_min_protocol_gate,
        // IO-thread-owned) and the auto-ratchet floor (m_runtime_min_protocol_version,
        // lifted 1700 -> 3600 on the compute thread by apply_min_protocol_ratchet).
        // Reading the atomic here is race-free; at the cold default (both 1700) every
        // real DASH peer is admitted (accept-all).
        const uint32_t effective_floor = std::max(
            m_min_protocol_gate.min_version,
            m_runtime_min_protocol_version.load(std::memory_order_relaxed));
        if (msg->m_version < effective_floor)
            throw std::runtime_error("peer protocol below min-protocol floor");

        peer->m_nonce = msg->m_nonce;
        m_peers[peer->m_nonce] = peer;

        // #754 join trigger (oracle p2p.py handle_version → node.py
        // handle_share_hashes): a peer advertising a best share we don't have
        // is THE download entry point for an empty node joining an
        // established chain. QUEUED, not called directly — download_shares
        // lives in node.cpp and this inline vtable body must stay link-free
        // for the rig-free KAT targets; run_think()'s IO phase and the
        // 2s advert timer (start_outbound_connections) drain the queue.
        if (!msg->m_best_share.IsNull())
        {
            LOG_INFO << "[Pool] Peer " << peer->addr().to_string()
                     << " advertises best share "
                     << msg->m_best_share.ToString().substr(0, 16)
                     << (m_chain->contains(msg->m_best_share)
                             ? " (known)" : " (unknown — queued for download)");
            m_peer_best_adverts.emplace_back(peer, msg->m_best_share);
        }

        // Legacy/actual split for the G2 dual-pool: only once the operator has
        // ratcheted the floor above the oracle baseline do at-or-above-floor
        // peers negotiate the actual (v36) protocol; otherwise legacy (parity
        // with the ltc reference, which returns legacy unconditionally).
        const bool ratcheted =
            effective_floor > SharechainConfig::MINIMUM_PROTOCOL_VERSION;
        return (ratcheted && msg->m_version >= effective_floor)
                   ? pool::PeerConnectionType::actual
                   : pool::PeerConnectionType::legacy;
    }

    // ── Reception-slice (B) dispatch surface ───────────────────
    // Declarations consumed by the Legacy/Actual protocol handlers
    // (protocol_legacy.cpp / protocol_actual.cpp). The bodies of
    // processing_shares() and handle_get_share() live in the node.cpp
    // translation unit (slice .4) and are intentionally link-deferred here;
    // the dispatch layer object-compiles against these declarations.
    void processing_shares(HandleSharesData& data, NetService addr);
    std::vector<dash::ShareType> handle_get_share(std::vector<uint256> hashes,
        uint64_t parents, std::vector<uint256> stops, NetService peer_addr);

    // Slice .4 helper: io_context-thread tracker insertion for a phase-1-
    // verified batch (non-blocking lock; defers to m_pending_adds if the
    // compute thread holds the exclusive lock). Body in node.cpp.
    void add_verified_shares(HandleSharesData& data, NetService addr);

    // ── Run-loop mint slice (3/3) surface — bodies in node.cpp ──────────
    // Ports of the btc::NodeImpl prod reference (src/impl/btc/node.cpp),
    // reconciled to the DASH pool-node. These make --run actually MINT:
    // stratum ShareAccept -> add_local_share -> broadcast_share, with think()
    // electing the best share the next job builds on.

    /// Open the LevelDB sharechain store for `net_name`, wire the verified-
    /// hash persistence + removal hooks, and load persisted shares into the
    /// tracker. Call ONCE from the run-loop before serving work.
    void init_storage(const std::string& net_name);
    void load_persisted_shares();
    /// Serialize one share into a LevelDB batch entry ([8B ver][contents]).
    void collect_share_batch_entry(ShareType& share,
        std::vector<c2pool::storage::SharechainStorage::ShareBatchEntry>& out);
    void flush_verified_to_leveldb();
    /// Flush pending persistence buffers (call at shutdown).
    void shutdown_persistence();

    /// Async best-chain selection: post tracker.think() to the compute
    /// thread (exclusive lock), publish m_best_share_hash + snapshot, then
    /// IO-phase: drain deferred share batches, fire on_best_share_changed,
    /// re-broadcast the new head. Serialized via m_think_running.
    void run_think();
    void drain_pending_adds();

    /// v36 accept-floor AutoRatchet — runtime wiring of the pure decision in
    /// auto_ratchet.hpp (mirrors dgb::NodeImpl::apply_min_protocol_ratchet, the
    /// three best-share-advance call sites in src/impl/dgb/node.cpp). Over the
    /// [CHAIN_LENGTH*9/10 .. CHAIN_LENGTH] window behind the best share's parent
    /// — the SAME window the 60% successor gate reads — lift the P2P accept floor
    /// 1700 -> 3600 once >= 95% of the work-weighted desired-version tally desires
    /// v36. Latched (never lowers), full-window-guarded (never lifts on a partial
    /// window), and DASH-specific keyed on the best share's m_desired_version (DASH
    /// has no v36 share TYPE — the vote carries v36-ness). MUST be called under the
    /// exclusive m_tracker_mutex. Body in node.cpp.
    void apply_min_protocol_ratchet();

    /// Periodic maintenance (btc node.cpp:1878-2173 / p2pool node.py:355-402
    /// clean_tracker port): think + eat stale heads + drop tails beyond
    /// 2*CHAIN_LENGTH+10 + LevelDB prune flush, all on the compute thread
    /// under the exclusive lock. Body in node.cpp; scheduled by the run
    /// loop's periodic tick. Without it the raw chain grows unbounded.
    void clean_tracker();

    /// Verified-work-first best share (mint_runloop.hpp elect_best_share
    /// policy — btc parity). ZERO with peers but no verified chain (never
    /// mint on an unverified foreign chain); raw-head bootstrap on genesis.
    /// (advertised_best_share — the peer-facing raw-head variant — is inline
    /// above, next to send_version.)
    uint256 best_share_hash();

    /// Pool-peer info for the dashboard node-status card (ltc node.hpp:302
    /// parity). Display only — MiningInterface::set_peer_info_fn feeds
    /// /local_stats {peers:{incoming,outgoing}} and the peer table. Read-only
    /// over the live m_peers map; touches no share/target/payout state.
    nlohmann::json get_peer_info_json() const {
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
        return arr;
    }

    /// Relay a share (and up to 4 un-broadcast ancestors) to all peers via
    /// the message_shares wire codec (+ remember_tx/forget_tx for txs the
    /// peer lacks). try_to_lock; deferred if the compute thread is busy.
    void broadcast_share(const uint256& share_hash);
    void send_shares(peer_ptr peer, const std::vector<uint256>& share_hashes);

    /// Insert a locally-minted, ALREADY self-verified share into the tracker
    /// (+ LevelDB persist + attempt_verify), then broadcast + run_think.
    /// Returns the share hash, or ZERO when the tracker lock is busy or the
    /// share is a duplicate (fail-closed: caller declines the mint).
    uint256 add_local_share(ShareType share);

    /// Register the current template's txs in m_known_txs so send_shares can
    /// serve remember_tx for a minted share's new_transaction_hashes. The
    /// previous template's leftovers are dropped (bounded by one template).
    void register_template_txs(const std::vector<coin::Transaction>& txs,
                               const std::vector<uint256>& hashes);

    void set_on_best_share_changed(std::function<void()> fn) { m_on_best_share_changed = std::move(fn); }
    void set_block_rel_height_fn(std::function<int32_t(uint256)> fn) { m_block_rel_height_fn = std::move(fn); }

    // ── #754 share-download leg surface ─────────────────────────────────

    /// Async share download: register the reply callback + dispatch the
    /// sharereq through the ctor's writer (ltc node.hpp:275-281 parity).
    void request_shares(uint256 id, peer_ptr peer,
                        std::vector<uint256> hashes, uint64_t parents,
                        std::vector<uint256> stops,
                        std::function<void(dash::ShareReplyData)> callback)
    {
        m_share_getter.request(id, callback, id, peer, hashes, parents, stops);
    }

    /// Request `target_hash` (+ a random 0..499-parent chunk, stops-bounded)
    /// from a peer; on reply, feed the shares into processing_shares and
    /// continue backfilling from the oldest parent. Body in node.cpp (ltc
    /// node.cpp:968-1105 port).
    void download_shares(peer_ptr peer, const uint256& target_hash);

    /// Drain the handle_version best-share advert queue into
    /// download_shares (unknown) / run_think (known). Body in node.cpp.
    void drain_peer_best_adverts();

    /// Dial outbound peers from the AddrStore (--addnode/--connect seeds) and
    /// start the 30s dial-maintenance + 2s advert-drain timers. Call once
    /// from the run loop after listen(). Body in node.cpp (ltc
    /// node.cpp:1289-1327 port).
    void start_outbound_connections();

    void set_target_outbound_peers(size_t count) { m_target_outbound_peers = count; }
    void set_max_peers(size_t count) { m_max_peers = count; }

    // Completes a pending async share request when a sharereply arrives.
    // Inline (mirrors dgb) so the reply-matcher plumbing needs no node.cpp.
    void got_share_reply(uint256 id, dash::ShareReplyData shares)
    {
        try { m_share_getter.got_response(id, shares); }
        catch (const std::invalid_argument&) { /* request already timed out */ }
    }

    // Register a callback fired when a bestblock message is received from a peer.
    void set_on_bestblock(std::function<void(const uint256&)> fn) { m_on_bestblock = std::move(fn); }

    // ── Tracker accessors ───────────────────────────────────────────────

    /// Direct tracker access — compute-thread-only (already holds the exclusive
    /// lock) or startup code (before the compute thread exists). IO-thread code
    /// MUST use read_tracker() instead.
    ShareTracker& tracker() { return m_tracker; }

    /// RAII guard for IO-thread tracker reads.
    /// - IO thread:      acquires shared_lock(try_to_lock); falsy if busy.
    /// - Compute thread: skips locking (exclusive already held); always truthy.
    class TrackerReadGuard {
        std::shared_lock<std::shared_mutex> lock_;
        ShareTracker& tracker_;
        bool ok_;
    public:
        TrackerReadGuard(std::shared_mutex& mtx, ShareTracker& t, bool on_compute)
            : lock_(mtx, std::defer_lock), tracker_(t)
        {
            if (on_compute) ok_ = true;          // exclusive lock already held
            else            ok_ = lock_.try_lock();
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
    bool is_compute_thread() const {
        return std::this_thread::get_id() == m_compute_thread_id.load(std::memory_order_relaxed);
    }

    /// Preferred tracker accessor for IO-thread callbacks. On the IO thread it
    /// acquires shared_lock(try_to_lock) (check `if (!guard)`); on the compute
    /// thread it skips locking (exclusive already held).
    TrackerReadGuard read_tracker() {
        return TrackerReadGuard(m_tracker_mutex, m_tracker, is_compute_thread());
    }

    /// Acquire shared (reader) lock on the tracker mutex — BLOCKING. Only for
    /// consensus-critical paths (share creation) where skipping is unacceptable.
    std::shared_lock<std::shared_mutex> tracker_shared_lock() {
        return std::shared_lock<std::shared_mutex>(m_tracker_mutex);
    }

    /// Expose the tracker mutex for IO-thread callbacks. Callers MUST use
    /// shared_lock(try_to_lock) — NEVER a blocking lock().
    std::shared_mutex& tracker_mutex() { return m_tracker_mutex; }

    // Embedded coin-state accessors (S8 embedded_gbt live-wire).
    /// The node-held embedded coin-state bundle (MN list + mempool + tip).
    coin::NodeCoinState&       coin_state()       { return m_coin_state; }
    const coin::NodeCoinState& coin_state() const { return m_coin_state; }

    /// The maintainer the reception/think slices drive as their updates land
    /// (on_mn_list_update / on_mempool_tx / on_new_tip / on_block_connected /
    /// on_invalidate). It republishes m_coin_state only once both a tip and a
    /// non-empty MN list are present.
    coin::CoinStateMaintainer& coin_state_maintainer() { return m_coin_state_maintainer; }

    /// Live get_work entry point: prefer the locally-assembled embedded
    /// template when the node-held bundle is populated, else the supplied
    /// dashd getblocktemplate fallback (REQUIRED -- always-reachable safety
    /// path + [GBT-XCHECK] cross-check). One-liner over NodeCoinState so the
    /// node call site (main_dash run path) is select_work(fallback).
    coin::WorkSelection select_work(
        const std::function<coin::DashWorkData()>& dashd_fallback)
    {
        return m_coin_state.select_work(dashd_fallback);
    }

    // ── Lock-free snapshot getters ──────────────────────────────────────
    // Inline (defined in this header) since slice A has no node.cpp. Never
    // fail, never need the tracker lock.
    TrackerSnapshot get_tracker_snapshot() const {
        std::lock_guard<std::mutex> lock(m_snapshot_mutex);
        return m_snapshot;
    }
    int get_chain_count() const {
        std::lock_guard<std::mutex> lock(m_snapshot_mutex);
        return m_snapshot.chain_count;
    }
    int get_verified_count() const {
        std::lock_guard<std::mutex> lock(m_snapshot_mutex);
        return m_snapshot.verified_count;
    }
};

// ── Sharechain-p2p dispatch layer (slice S8-p2p.2) ──────────────────
// Namespace-only port of the dgb reference (src/impl/dgb/node.hpp:647). The
// version-handshake reception rides NodeImpl::handle_version above; the two
// established-peer protocols below dispatch the 12 post-handshake messages.
// Both Legacy and Actual register the identical handler set; the divergence
// between them lives in the handler BODIES (protocol_legacy.cpp vs
// protocol_actual.cpp), byte-parity with dgb. handle_message() bodies + the
// 12 HANDLER() bodies are defined in those two .cpp translation units.

class Legacy : public pool::Protocol<NodeImpl>
{
public:
    void handle_message(std::unique_ptr<RawMessage> rmsg, NodeImpl::peer_ptr peer) override;

    ADD_HANDLER(addrs, dash::message_addrs);
    ADD_HANDLER(addrme, dash::message_addrme);
    ADD_HANDLER(ping, dash::message_ping);
    ADD_HANDLER(getaddrs, dash::message_getaddrs);
    ADD_HANDLER(shares, dash::message_shares);
    ADD_HANDLER(sharereq, dash::message_sharereq);
    ADD_HANDLER(sharereply, dash::message_sharereply);
    ADD_HANDLER(bestblock, dash::message_bestblock);
    ADD_HANDLER(have_tx, dash::message_have_tx);
    ADD_HANDLER(losing_tx, dash::message_losing_tx);
    ADD_HANDLER(remember_tx, dash::message_remember_tx);
    ADD_HANDLER(forget_tx, dash::message_forget_tx);
};

class Actual : public pool::Protocol<NodeImpl>
{
public:
    void handle_message(std::unique_ptr<RawMessage> rmsg, NodeImpl::peer_ptr peer) override;

    ADD_HANDLER(addrs, dash::message_addrs);
    ADD_HANDLER(addrme, dash::message_addrme);
    ADD_HANDLER(ping, dash::message_ping);
    ADD_HANDLER(getaddrs, dash::message_getaddrs);
    ADD_HANDLER(shares, dash::message_shares);
    ADD_HANDLER(sharereq, dash::message_sharereq);
    ADD_HANDLER(sharereply, dash::message_sharereply);
    ADD_HANDLER(bestblock, dash::message_bestblock);
    ADD_HANDLER(have_tx, dash::message_have_tx);
    ADD_HANDLER(losing_tx, dash::message_losing_tx);
    ADD_HANDLER(remember_tx, dash::message_remember_tx);
    ADD_HANDLER(forget_tx, dash::message_forget_tx);
};

using Node = pool::NodeBridge<NodeImpl, Legacy, Actual>;

} // namespace dash