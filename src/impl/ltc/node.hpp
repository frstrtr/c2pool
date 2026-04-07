#pragma once

#include "config.hpp"
#include "share.hpp"
#include "share_tracker.hpp"
#include "peer.hpp"
#include "messages.hpp"

#include <pool/node.hpp>
#include <pool/protocol.hpp>
#include <core/message.hpp>
#include <core/reply_matcher.hpp>
#include <sharechain/prepared_list.hpp>
#include <c2pool/storage/sharechain_storage.hpp>

#include <atomic>
#include <chrono>
#include <mutex>
#include <random>

namespace ltc
{
struct HandleSharesData;
struct ShareReplyData
{
    std::vector<ShareType> m_items;
    std::vector<chain::RawShare> m_raw_items;
};

class NodeImpl : public pool::BaseNode<ltc::Config, ltc::ShareChain, ltc::Peer>
{
    // Async share downloader:
    // ID = uint256 (matches sharereq id to sharereply id)
    // RESPONSE = parsed shares plus their original raw payloads
    // REQUEST args: req_id, peer, hashes, parents, stops
    using share_getter_t = ReplyMatcher::ID<uint256>
        ::RESPONSE<ltc::ShareReplyData>
        ::REQUEST<uint256, peer_ptr, std::vector<uint256>, uint64_t, std::vector<uint256>>;

protected:
    ltc::Handler m_handler;
    share_getter_t m_share_getter;
    ShareTracker m_tracker;
    std::unique_ptr<c2pool::storage::SharechainStorage> m_storage;

    // Global pool of known transactions, populated by remember_tx and coin daemon.
    // Protocol handlers look up tx hashes here when processing shares.
    std::map<uint256, coin::Transaction> m_known_txs;

    // Thread pool for parallel share_init_verify (scrypt CPU work).
    // Keeps expensive crypto off the io_context thread.
    boost::asio::thread_pool m_verify_pool{4};

    // Dedicated single thread for think() validation (Litecoin Core pattern:
    // validation runs on its own thread, never blocking the net/ioc thread).
    // m_cs_tracker serializes access to m_tracker between think_pool and ioc,
    // matching Litecoin Core's cs_main mutex pattern.
    boost::asio::thread_pool m_think_pool{1};
    std::atomic<bool> m_think_running{false};
    std::atomic<bool> m_clean_running{false};
    std::recursive_mutex m_cs_tracker;

    // Top-5 scored heads from last think() — used by clean_tracker()
    // to protect the best chains from head pruning (p2pool node.py:363).
    std::vector<uint256> m_last_top5_heads;

    // Buffer of newly verified share hashes, flushed to LevelDB periodically
    std::vector<uint256> m_verified_flush_buf;

    // Buffer of pruned share hashes, batch-deleted from LevelDB after clean_tracker()
    std::vector<uint256> m_removal_flush_buf;

public:
    NodeImpl()
        : m_share_getter(nullptr,
            [](uint256, peer_ptr, std::vector<uint256>, uint64_t, std::vector<uint256>){}) {}

    NodeImpl(boost::asio::io_context* ctx, config_t* config)
        : base_t(ctx, config),
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

        // Wire up share removal → LevelDB cleanup (p2pool main.py:269-270)
        // Buffer removals; clean_tracker() flushes after drop-tails.
        // Safe on crash: unflushed shares get pruned at next startup by load_persisted_shares().
        m_tracker.chain.on_removed([this](const uint256& hash) {
            m_removal_flush_buf.push_back(hash);
        });
    }

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
    void processing_shares(HandleSharesData& data, NetService addr);
    void processing_shares_phase2(HandleSharesData& data, NetService addr);
    ShareTracker& tracker() { return m_tracker; }

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

    /// Return a JSON array of connected peer info for the /peer_list endpoint.
    nlohmann::json get_peer_info_json() const {
        nlohmann::json arr = nlohmann::json::array();
        for (const auto& [nonce, peer] : m_peers) {
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
                {"txpool_size", static_cast<int>(peer->m_remembered_txs.size())},
                {"web_port", 0}
            });
        }
        return arr;
    }

    /// Register a callback invoked whenever a bestblock message is received
    /// from any peer (after relaying). Use this to trigger work refresh.
    void set_on_bestblock(std::function<void()> fn) { m_on_bestblock = std::move(fn); }

    /// Send a set of shares (with any needed txs) to a single peer.
    /// Skips shares that originated from that peer.
    void send_shares(peer_ptr peer, const std::vector<uint256>& share_hashes);

    /// Broadcast a locally-generated (or newly-received) share to all peers.
    void broadcast_share(const uint256& share_hash);

    /// Start downloading shares from a peer, beginning at `target_hash`.
    /// Recursively fetches parents until the chain is connected or CHAIN_LENGTH reached.
    void download_shares(peer_ptr peer, const uint256& target_hash);

    /// Return the hash of our tallest chain head, or uint256::ZERO if empty.
    uint256 best_share_hash();

    /// Load persisted shares from LevelDB storage into the tracker.
    void load_persisted_shares();
    void flush_verified_to_leveldb();

    /// Graceful shutdown: flush pending verified/removal buffers to LevelDB.
    void shutdown();

    /// Start dialing outbound peers from AddrStore / bootstrap list.
    /// Maintains target outbound peer count active outbound connections.
    void start_outbound_connections();

    /// Set desired number of outbound peers maintained by connection loop.
    /// A value of 0 disables outbound dialing.
    void set_target_outbound_peers(size_t count) { m_target_outbound_peers = count; }

    /// Set max total P2P peers (inbound + outbound).
    void set_max_peers(size_t count) { m_max_peers = count; }

    /// Set P2P ban duration (seconds).
    void set_ban_duration(int seconds) { m_ban_duration = std::chrono::seconds(seconds); }

    /// Set cache size limits for memory control.
    void set_cache_limits(size_t max_shared, size_t max_known_txs, size_t max_raw) {
        m_max_shared_hashes = max_shared;
        m_max_known_txs = max_known_txs;
        m_max_raw_shares = max_raw;
    }

    /// Set RSS memory limit in MB (abort if exceeded). Static because checked in process_shares.
    static void set_rss_limit_mb(long mb);

    /// Unified share retention: single-pass prune of chain + verified + LevelDB.
    /// Replaces multi-pass trim with work-based dead head detection and
    /// deferred destruction for verified cascade safety.
    /// Called from run_think() on the ioc thread.
    void prune_shares(const uint256& best_share);

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

    /// Set the block_rel_height function used by run_think() for chain scoring.
    /// fn(block_hash) should return confirmations from the coin daemon:
    ///   >= 0 : block is in main chain (0 = tip, higher = deeper)
    ///   <  0 : block is NOT in main chain (orphaned/stale)
    using block_rel_height_fn_t = std::function<int32_t(uint256)>;
    void set_block_rel_height_fn(block_rel_height_fn_t fn) { m_block_rel_height_fn = std::move(fn); }

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
    bool is_banned(const NetService& addr) const;

protected:
    std::function<void()> m_on_bestblock;
    std::function<void()> m_on_best_share_changed;
    std::function<double()> m_local_hashrate_fn;
    std::function<LocalRateStats()> m_local_rate_stats_fn;
    std::function<std::vector<std::pair<std::string, uint64_t>>()> m_current_pplns_fn;
    std::function<std::vector<std::string>()> m_local_miner_scripts_fn;
    std::string m_node_payout_script_hex;
    std::set<uint256> m_shared_share_hashes;  // de-dup set for broadcast_share
    std::set<uint256> m_rejected_share_hashes; // shares rejected by peers — never re-broadcast
    std::set<uint256> m_downloading_shares;   // hashes currently being fetched

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
    std::set<NetService> m_pending_outbound;   // addresses currently being dialed
    std::set<NetService> m_outbound_addrs;     // successfully connected outbound peers

    // Peer banning: maps address → ban expiry time
    std::map<NetService, std::chrono::steady_clock::time_point> m_ban_list;
    std::chrono::seconds m_ban_duration{300}; // 5 minutes (configurable)

    // Rate-limit run_think(): minimum interval between calls
    std::chrono::steady_clock::time_point m_last_think_time{};
    // p2pool: 0ms (synchronous, no rate limit). Match exactly.
    static constexpr std::chrono::milliseconds THINK_MIN_INTERVAL{0};

    // Cache limits (configurable)
    size_t m_max_shared_hashes = 50000;
    size_t m_max_known_txs     = 10000;
    size_t m_max_raw_shares    = 50000;

    // Block depth function for chain scoring (set via set_block_rel_height_fn)
    block_rel_height_fn_t m_block_rel_height_fn;

    // Cached best share hash from the most recent think() cycle
    uint256 m_best_share_hash;

    // Cache of original raw serialized bytes keyed by share hash.
    // Used for relay so we send the exact bytes we received, avoiding
    // any round-trip serialization differences.
    std::unordered_map<uint256, chain::RawShare, ShareHasher> m_raw_share_cache;
};

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
