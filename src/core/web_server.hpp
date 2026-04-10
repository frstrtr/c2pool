#pragma once

#include <memory>
#include <string>
#include <functional>
#include <thread>
#include <atomic>
#include <mutex>
#include <future>
#include <set>
#include <map>
#include <unordered_map>
#include <array>
#include <iomanip>
#include <sstream>
#include <ctime>

#include <boost/asio.hpp>
#include <boost/beast.hpp>
#include <boost/process.hpp>
#include <nlohmann/json.hpp>
#include <jsonrpccxx/server.hpp>

#include <core/log.hpp>
#include <core/uint256.hpp>
#include <core/mining_node_interface.hpp>
#include <core/address_validator.hpp>
#include <c2pool/payout/payout_manager.hpp>
#include <c2pool/hashrate/tracker.hpp>
#include <core/address_utils.hpp>

// Forward declaration for merged mining integration
namespace c2pool { namespace merged { class MergedMiningManager; } }

// Bring the address validation types into the core namespace for convenience
using Blockchain = c2pool::address::Blockchain;
using Network = c2pool::address::Network;
using AddressValidationResult = c2pool::address::AddressValidationResult;
using BlockchainAddressValidator = c2pool::address::BlockchainAddressValidator;

// Forward declarations for optional coin daemon integration (avoid layering violation)
namespace ltc { namespace coin { class NodeRPC; } }
namespace ltc { namespace coin { class CoinNodeInterface; } }
namespace ltc { namespace interfaces { struct Node; } }

namespace core {

namespace beast = boost::beast;
namespace http = beast::http;
namespace net = boost::asio;
using tcp = net::ip::tcp;

// Forward declarations
class MiningInterface;
class StratumServer;
class LitecoinRpcClient;

/// Litecoin Core RPC client for blockchain sync status
class LitecoinRpcClient
{
public:
    LitecoinRpcClient(bool testnet = true);
    
    struct SyncStatus {
        bool is_synced;
        double progress;
        uint64_t current_blocks;
        uint64_t total_headers;
        bool initial_block_download;
        std::string error_message;
    };
    
    SyncStatus get_sync_status();
    bool is_connected();
    std::string execute_cli_command(const std::string& command);
    
private:
    bool testnet_;
};

/// HTTP Session handler for incoming connections
class HttpSession : public std::enable_shared_from_this<HttpSession>
{
    tcp::socket socket_;
    beast::flat_buffer buffer_;
    http::request<http::string_body> request_;
    std::shared_ptr<MiningInterface> mining_interface_;

public:
    explicit HttpSession(tcp::socket socket, std::shared_ptr<MiningInterface> mining_interface);
    void run();

private:
    void read_request();
    void process_request();
    void send_response(http::response<http::string_body> response);
    void handle_error(beast::error_code ec, char const* what);
};

/// Stratum mining configuration — tuneable from CLI, YAML, or API.
struct StratumConfig {
    double min_difficulty       = 0.0005;   // floor for per-connection vardiff
    double max_difficulty       = 65536.0;  // ceiling for per-connection vardiff
    double target_time          = 3.0;      // seconds between pseudoshares (p2pool default: 3)
    bool   vardiff_enabled      = true;     // auto-adjust per-connection difficulty
    size_t max_coinbase_outputs = 4000;     // Python p2pool's [-4000:] cap; no consensus limit
};

/// Mining interface that provides RPC methods for miners
class MiningInterface : public jsonrpccxx::JsonRpc2Server
{
public:
    MiningInterface(bool testnet = false, std::shared_ptr<IMiningNode> node = nullptr, Blockchain blockchain = Blockchain::LITECOIN);

    // Core mining methods that miners expect
    nlohmann::json getwork(const std::string& request_id = "");
    nlohmann::json submitwork(const std::string& nonce, const std::string& header, const std::string& mix, const std::string& request_id = "");
    nlohmann::json getblocktemplate(const nlohmann::json& params = nlohmann::json::array(), const std::string& request_id = "");
    nlohmann::json submitblock(const std::string& hex_data, const std::string& request_id = "");
    
    // Pool stats and info methods
    nlohmann::json getinfo(const std::string& request_id = "");
    nlohmann::json getstats(const std::string& request_id = "");
    nlohmann::json getpeerinfo(const std::string& request_id = "");

    // p2pool-compatible REST endpoints (return plain JSON, not JSON-RPC)
    nlohmann::json rest_local_rate();
    nlohmann::json rest_global_rate();
    nlohmann::json rest_current_payouts();
    nlohmann::json rest_users();
    nlohmann::json rest_fee();
    nlohmann::json rest_recent_blocks();

    // THE checkpoint endpoints
    nlohmann::json rest_checkpoint();    // latest verified checkpoint
    nlohmann::json rest_checkpoints();   // all checkpoints

    // Current work state for THE checkpoint creation
    struct CurrentTheState {
        uint256 the_state_root;
        uint32_t sharechain_height{0};
        uint16_t miner_count{0};
        double pool_hashrate{0};
    };
    CurrentTheState get_current_work() const {
        CurrentTheState s;
        s.the_state_root = m_cached_the_state_root;
        s.sharechain_height = m_cached_sharechain_height;
        s.miner_count = m_cached_miner_count;
        s.pool_hashrate = m_cached_pool_hashrate;
        return s;
    }

    // THE checkpoint management
    using checkpoint_store_fn_t = std::function<nlohmann::json()>;                  // get latest
    using checkpoints_all_fn_t = std::function<nlohmann::json()>;                   // get all
    using checkpoint_verify_fn_t = std::function<bool(const uint256&, uint32_t)>;   // verify state_root
    using checkpoint_create_fn_t = std::function<void(const std::string& chain, uint64_t height,
                                                       const std::string& hash, uint64_t ts)>;
    void set_checkpoint_fns(checkpoint_store_fn_t latest, checkpoints_all_fn_t all_fn,
                            checkpoint_verify_fn_t verify_fn,
                            checkpoint_create_fn_t create_fn = {}) {
        m_checkpoint_latest_fn = std::move(latest);
        m_checkpoints_all_fn = std::move(all_fn);
        m_checkpoint_verify_fn = std::move(verify_fn);
        m_checkpoint_create_fn = std::move(create_fn);
    }

    // Monitoring endpoints for Qt control panel
    nlohmann::json rest_uptime();
    nlohmann::json rest_connected_miners();
    nlohmann::json rest_stratum_stats();
    nlohmann::json rest_miner_thresholds();
    nlohmann::json rest_global_stats();
    nlohmann::json rest_sharechain_stats();
    nlohmann::json rest_sharechain_window();
    // Returns cached+serialized window JSON string (for ETag/cache layer)
    std::pair<std::string, std::string> get_cached_window_response(); // {json_body, etag}
    nlohmann::json rest_sharechain_tip();
    nlohmann::json rest_sharechain_delta(const std::string& since_hash);
    nlohmann::json rest_control_mining_start();
    nlohmann::json rest_control_mining_stop();
    nlohmann::json rest_control_mining_restart();
    nlohmann::json rest_control_mining_ban(const std::string& target);
    nlohmann::json rest_control_mining_unban(const std::string& target);

    // p2pool-compatible legacy REST endpoints (enable original p2pool dashboards)
    nlohmann::json rest_local_stats();
    nlohmann::json rest_p2pool_global_stats();
    nlohmann::json rest_web_version();
    nlohmann::json rest_web_currency_info();
    nlohmann::json rest_payout_addr();
    nlohmann::json rest_payout_addrs();
    nlohmann::json rest_web_best_share_hash();

    // Additional p2pool-compatible REST endpoints (peer network, stale rates, mining details)
    nlohmann::json rest_rate();                     // /rate — pool hashrate (single number)
    nlohmann::json rest_difficulty();               // /difficulty — share difficulty (single number)
    nlohmann::json rest_user_stales();              // /user_stales — per-user stale proportions
    std::string    rest_peer_addresses();           // /peer_addresses — space-separated peer list (text)
    nlohmann::json rest_peer_versions();            // /peer_versions — p2pool version per peer
    nlohmann::json rest_peer_txpool_sizes();        // /peer_txpool_sizes — txpool size per peer
    nlohmann::json rest_peer_list();                // /peer_list — detailed peer list [{address,version,incoming,uptime,...}]
    nlohmann::json rest_pings();                    // /pings — ping latency per peer (stub)
    nlohmann::json rest_stale_rates();              // /stale_rates — {good,orphan,dead} rate breakdown
    nlohmann::json rest_node_info();                // /node_info — {external_ip,worker_port,p2p_port,network,symbol}
    nlohmann::json rest_luck_stats();               // /luck_stats — pool luck statistics
    nlohmann::json rest_ban_stats();                // /ban_stats — current ban statistics
    nlohmann::json rest_stratum_security();         // /stratum_security — DDoS detection metrics (stub)
    nlohmann::json rest_miner_stats(const std::string& address);  // /miner_stats/<addr> — detailed per-miner stats
    nlohmann::json rest_best_share();               // /best_share — node-wide best share (BitAxe style)
    nlohmann::json rest_miner_payouts(const std::string& address); // /miner_payouts/<addr> — payout history per miner
    nlohmann::json rest_version_signaling(const nlohmann::json* cached_sc = nullptr); // /version_signaling — V36 version tracking
    nlohmann::json rest_v36_status();                // /v36_status — V36 diagnostic
    nlohmann::json rest_patron_sendmany(const std::string& total); // /patron_sendmany/<total> — sendmany text
    nlohmann::json rest_tracker_debug();             // /tracker_debug — debug sharechain info

    // Merged mining endpoints
    nlohmann::json rest_merged_stats();              // /merged_stats — merged mining statistics
    nlohmann::json rest_current_merged_payouts();    // /current_merged_payouts — cached wrapper
    nlohmann::json compute_current_merged_payouts(); // full computation (main thread only)
    nlohmann::json rest_recent_merged_blocks();      // /recent_merged_blocks — recent merged blocks
    nlohmann::json rest_all_merged_blocks();         // /all_merged_blocks — all merged blocks
    nlohmann::json rest_discovered_merged_blocks();  // /discovered_merged_blocks — merged block proofs
    nlohmann::json rest_broadcaster_status();        // /broadcaster_status — parent chain broadcaster
    nlohmann::json rest_merged_broadcaster_status(); // /merged_broadcaster_status — merged broadcaster
    nlohmann::json rest_network_difficulty();         // /network_difficulty — historical network diff

    // /web/ sub-endpoints (share chain inspection)
    nlohmann::json rest_web_heads();                 // /web/heads
    nlohmann::json rest_web_verified_heads();        // /web/verified_heads
    nlohmann::json rest_web_tails();                 // /web/tails
    nlohmann::json rest_web_verified_tails();        // /web/verified_tails
    nlohmann::json rest_web_my_share_hashes();       // /web/my_share_hashes
    nlohmann::json rest_web_my_share_hashes50();     // /web/my_share_hashes50
    nlohmann::json rest_web_share(const std::string& hash); // /web/share/<hash>
    nlohmann::json rest_web_payout_address(const std::string& hash); // /web/payout_address/<hash>
    nlohmann::json rest_web_log_json();              // /web/log — JSON array (p2pool stat_log format)
    nlohmann::json rest_web_graph_data(const std::string& source, const std::string& view); // /web/graph_data/<source>/<view>

    // Log endpoints for Qt PageLogs — read directly from debug.log
    std::string rest_web_log();
    std::string rest_logs_export(const std::string& scope, int64_t from_ts, int64_t to_ts, const std::string& format);

    // Track a found block for the /recent_blocks endpoint.
    // Extended overload captures dashboard-enriched fields at record time.
    void record_found_block(uint64_t height, const uint256& hash, uint64_t ts = 0,
                            const std::string& chain = "LTC",
                            const std::string& miner = "",
                            const std::string& share_hash = "",
                            double network_difficulty = 0,
                            double share_difficulty = 0,
                            double pool_hashrate = 0,
                            uint64_t subsidy = 0);
    
    // Frozen share fields returned by ref_hash_fn — must be defined before JobSnapshot.
    struct RefHashResult {
        uint256  ref_hash;
        uint64_t last_txout_nonce{0};
        uint32_t absheight{0};
        uint128  abswork;
        uint256  far_share_hash;
        uint32_t max_bits{0};
        uint32_t bits{0};
        uint32_t timestamp{0};
        uint256  merged_payout_hash;
        int64_t  share_version{36};     // AutoRatchet: V35 or V36
        uint64_t desired_version{36};   // Version vote (always target version)
        // Frozen mm_commitment — built atomically with merged_coinbase_info headers
        // by build_merged_header_info_with_commitment(). Empty if no merged mining.
        std::vector<uint8_t> frozen_mm_commitment;
        // Frozen segwit data — merkle branches and witness root change between
        // GBT updates, but the ref_hash was computed with the values at template time.
        std::vector<uint256> frozen_merkle_branches;
        uint256  frozen_witness_root;
        // V36: frozen merged coinbase info (pre-serialized vector<MergedCoinbaseEntry>)
        // Contains DOGE block header + merkle proof for consensus verification.
        std::vector<unsigned char> frozen_merged_coinbase_info;
    };

    // Stratum-style methods (for advanced miners)
    // Job snapshot: holds all template data frozen at the time a mining job was sent.
    struct JobSnapshot {
        std::string coinb1, coinb2;
        std::string gbt_prevhash;      // BE display hex
        std::string nbits;             // BE hex e.g. "1e0fffff" (share target bits for header)
        uint32_t    version{0};
        std::vector<std::string> merkle_branches;
        std::vector<std::string> tx_data;   // raw tx hex from GBT
        std::string mweb;
        bool        segwit_active{false};
        uint256     prev_share_hash;  // share chain tip when this job was built
        uint64_t    subsidy{0};       // coinbasevalue frozen at job creation
        std::string witness_commitment_hex;  // P2Pool witness commitment frozen at job creation
        uint256     witness_root;            // raw wtxid merkle root frozen at job creation
        uint32_t    share_bits{0};    // share target bits from compute_share_target()
        uint32_t    share_max_bits{0}; // share max_bits from compute_share_target()
        std::string block_nbits;      // original GBT block bits (for block target check)
        RefHashResult frozen_ref;     // frozen share fields from template time
        int stale_info{0};            // 0=none, 253=orphan (stale block template)
    };
    nlohmann::json mining_subscribe(const std::string& user_agent = "", const std::string& request_id = "");
    nlohmann::json mining_authorize(const std::string& username, const std::string& password, const std::string& request_id = "");
    nlohmann::json mining_submit(const std::string& username, const std::string& job_id, const std::string& extranonce1, const std::string& extranonce2, const std::string& ntime, const std::string& nonce, const std::string& request_id = "",
        const std::map<uint32_t, std::vector<unsigned char>>& merged_addresses = {},
        const JobSnapshot* job = nullptr);

    // Enhanced coinbase and validation methods
    nlohmann::json validate_address(const std::string& address);
    nlohmann::json build_coinbase(const nlohmann::json& params);
    nlohmann::json validate_coinbase(const std::string& coinbase_hex);
    nlohmann::json getblockcandidate(const nlohmann::json& params = nlohmann::json::object());

    // Address validation
    bool is_valid_address(const std::string& address) const;
    
    // Get current blockchain and network configuration
    Blockchain get_blockchain() const { return m_blockchain; }
    Network get_network() const { return m_testnet ? Network::TESTNET : Network::MAINNET; }
    
    // Access to address validator (for Stratum sessions)
    const BlockchainAddressValidator& get_address_validator() const { return m_address_validator; }
    
    // Access to payout manager (for Stratum sessions)
    c2pool::payout::PayoutManager* get_payout_manager() const { return m_payout_manager.get(); }
    
    // Sync status checking
    bool is_blockchain_synced() const;
    void log_sync_progress() const;
    
    // Difficulty calculation utilities
    double calculate_share_difficulty(const std::string& job_id, const std::string& extranonce1,
                                     const std::string& extranonce2, 
                                     const std::string& ntime, const std::string& nonce) const;
    double calculate_share_difficulty(const std::string& coinb1, const std::string& coinb2,
                                     const std::string& extranonce1, const std::string& extranonce2,
                                     const std::string& ntime, const std::string& nonce) const;

    // Fully self-contained difficulty calculation: all template data passed in.
    // Does NOT acquire m_work_mutex — safe to call from any thread.
    static double calculate_share_difficulty(
        const std::string& coinb1, const std::string& coinb2,
        const std::string& extranonce1, const std::string& extranonce2,
        const std::string& ntime, const std::string& nonce,
        uint32_t version, const std::string& prevhash_hex,
        const std::string& nbits_hex,
        const std::vector<std::string>& merkle_branches);

    // Hook: returns the best share hash from the share tracker (for prev_hash wiring)
    void set_best_share_hash_fn(std::function<uint256()> fn) { m_best_share_hash_fn = thread_safe_wrap(std::move(fn)); }
    std::function<uint256()> get_best_share_hash_fn() const { return m_best_share_hash_fn; }

    // Hook: walk back from best_share to find nearest peer share for work template.
    // Ensures c2pool shares extend the main chain, not local forks.
    using find_peer_prev_fn_t = std::function<uint256(const uint256&)>;
    void set_find_peer_prev_fn(find_peer_prev_fn_t fn) { m_find_peer_prev_fn = std::move(fn); }
    find_peer_prev_fn_t get_find_peer_prev_fn() const { return m_find_peer_prev_fn; }

    // Hook: computes PPLNS expected payouts from the share tracker
    using pplns_fn_t = std::function<std::map<std::vector<unsigned char>, double>(
        const uint256& best_hash, const uint256& block_target,
        uint64_t subsidy, const std::vector<unsigned char>& donation_script)>;
    void set_pplns_fn(pplns_fn_t fn) { m_pplns_fn = thread_safe_wrap(std::move(fn)); }

    // Hook: computes the p2pool ref_hash for a given coinbase scriptSig.
    // Returns (ref_hash, last_txout_nonce) pair.  The ref_hash depends on
    // the share tracker state (prev_share, absheight, abswork, etc.) and
    // the miner's payout address (implicit via existing connection state).
    // Called per-connection during work generation.
    using ref_hash_fn_t = std::function<RefHashResult(
        const uint256& prev_share_hash,
        const std::vector<unsigned char>& coinbase_scriptSig,
        const std::vector<unsigned char>& payout_script,
        uint64_t subsidy, uint32_t bits, uint32_t timestamp,
        bool segwit_active, const std::string& witness_commitment_hex,
        const uint256& witness_root,
        const std::vector<std::pair<uint32_t, std::vector<unsigned char>>>& merged_addrs,
        const std::vector<uint256>& merkle_branches)>;
    void set_ref_hash_fn(ref_hash_fn_t fn) { m_ref_hash_fn = std::move(fn); }

    // Atomically snapshot work-related fields under m_work_mutex.
    // Used by StratumSession to freeze consistent state matching the coinbase.
    struct WorkSnapshot {
        bool segwit_active{false};
        std::string mweb;
        uint64_t subsidy{0};
        std::string witness_commitment_hex;
        uint256 witness_root;
        // Frozen share fields from ref_hash_fn
        RefHashResult frozen_ref;
        // Block body data — must be captured atomically with witness_commitment
        // to prevent merkle root mismatch when refresh_work() updates the template.
        std::vector<std::string> tx_data;              // raw tx hex from template
        std::vector<std::string> merkle_branches;      // stratum merkle branches
    };

    // Build per-connection coinbase parts: computes ref_hash using the ref_hash callback,
    // then generates coinb1/coinb2 with full output set including OP_RETURN.
    // prev_share_hash is frozen at the caller and passed in to avoid race conditions.
    // Also returns work snapshot atomically (under same lock) to prevent race with refresh_work.
    // Returns (coinb1, coinb2) or empty strings if not possible.
    struct CoinbaseResult {
        std::string coinb1;
        std::string coinb2;
        WorkSnapshot snapshot;
    };
    CoinbaseResult build_connection_coinbase(
        const uint256& prev_share_hash,
        const std::string& extranonce1_hex,
        const std::vector<unsigned char>& payout_script,
        const std::vector<std::pair<uint32_t, std::vector<unsigned char>>>& merged_addrs) const;

    // Hook: called by mining_submit() pool path to create a share in the tracker.
    // All block template data needed by create_local_share() is passed through.
    struct ShareCreationParams {
        std::string miner_address;  // Stratum username (human-readable address)
        std::vector<unsigned char> payout_script;
        std::map<uint32_t, std::vector<unsigned char>> merged_addresses;
        uint32_t block_version{0};
        uint256  prev_block_hash;
        uint32_t timestamp{0};
        uint32_t bits{0};          // share chain target bits (share.m_bits)
        uint32_t block_bits{0};   // GBT block difficulty (min_header.m_bits in the 80-byte header)
        uint32_t nonce{0};
        std::vector<unsigned char> coinbase_scriptSig;  // BIP34 height + pool tag
        uint64_t subsidy{0};
        std::vector<uint256> merkle_branches;
        int stale_info{0};  // 0=none, 253=orphan, 254=doa
        bool segwit_active{false};
        std::string witness_commitment_hex;  // P2Pool witness commitment script hex
        uint256 witness_root;                // raw wtxid merkle root (for SegwitData)
        std::vector<unsigned char> full_coinbase_bytes;  // actual mined coinbase TX for hash_link
        std::vector<unsigned char> message_data;         // optional V36 authority message blob
        uint256 prev_share_hash;  // share chain tip at work-generation time

        // Frozen share fields from ref_hash_fn (template creation time).
        // These MUST match what was used to compute the ref_hash in the coinbase.
        // If create_local_share recomputes them from current tracker state,
        // they may differ → ref_hash mismatch → peer rejection.
        uint32_t frozen_absheight{0};
        uint128  frozen_abswork;
        uint256  frozen_far_share_hash;
        uint32_t frozen_max_bits{0};
        uint32_t frozen_bits{0};     // share target at template time
        uint32_t frozen_timestamp{0};
        uint256  frozen_merged_payout_hash;
        std::vector<uint256> frozen_merkle_branches;  // segwit txid_merkle_link branches at template time
        uint256  frozen_witness_root;                  // wtxid_merkle_root at template time
        std::vector<unsigned char> frozen_merged_coinbase_info;  // pre-serialized MergedCoinbaseEntry vector
        bool     has_frozen_fields{false};  // true if the above are valid

        // AutoRatchet share version (V35 or V36) — determined at template time
        int64_t  share_version{36};
        uint64_t desired_version{36};
    };
    using create_share_fn_t = std::function<void(const ShareCreationParams& params)>;
    void set_create_share_fn(create_share_fn_t fn) { m_create_share_fn = std::move(fn); }

    // Operator-controlled V36 message blob to embed into locally created shares.
    // Empty means no message_data in locally produced shares.
    void set_operator_message_blob(const std::vector<unsigned char>& blob);
    std::vector<unsigned char> get_operator_message_blob() const;

    // Coinbase scriptSig customization (--coinbase-text)
    void set_coinbase_text(const std::string& text) { m_coinbase_text = text; }
    const std::string& get_coinbase_text() const { return m_coinbase_text; }

    // Load transition message blobs from a directory (*.hex files).
    // Decrypts and caches messages for display in the transition banner.
    void load_transition_blobs(const std::string& dir_path);

    // Hook: expose decoded protocol messages (e.g. from current best share)
    // through API methods for dashboard/monitoring clients.
    using protocol_messages_fn_t = std::function<nlohmann::json()>;
    void set_protocol_messages_fn(protocol_messages_fn_t fn) { m_protocol_messages_fn = thread_safe_wrap(std::move(fn)); }

    // Integrated merged mining manager
    void set_merged_mining_manager(c2pool::merged::MergedMiningManager* mgr) { m_mm_manager = mgr; }
    c2pool::merged::MergedMiningManager* get_mm_manager() const { return m_mm_manager; }

    // Cached merged header info — built atomically with mm_commitment
    struct CachedMergedHeaderInfo {
        uint32_t chain_id{0};
        uint64_t coinbase_value{0};
        uint32_t block_height{0};
        std::vector<unsigned char> block_header;
        std::vector<uint256> coinbase_merkle_branches;
        std::vector<unsigned char> coinbase_script;
        std::string coinbase_hex;
    };
    const std::vector<CachedMergedHeaderInfo>& get_last_merged_header_infos() const { return m_last_merged_header_infos; }
    double get_local_hashrate() const { return m_cached_pool_hashrate; }
    void set_local_hashrate(double hr) { m_cached_pool_hashrate = hr; }
    double get_network_difficulty() const { return m_network_difficulty.load(); }

    // Sharechain stats callback — returns live tracker data for the /sharechain/stats endpoint
    using sharechain_stats_fn_t = std::function<nlohmann::json()>;
    void set_sharechain_stats_fn(sharechain_stats_fn_t fn) { m_sharechain_stats_fn = thread_safe_wrap(std::move(fn)); }

    // Sharechain window callback — returns per-share data for the defragmenter grid
    using sharechain_window_fn_t = std::function<nlohmann::json()>;
    void set_sharechain_window_fn(sharechain_window_fn_t fn) { m_sharechain_window_fn = thread_safe_wrap(std::move(fn)); }

    // Sharechain tip callback — returns {hash, height} for lightweight polling
    using sharechain_tip_fn_t = std::function<nlohmann::json()>;
    void set_sharechain_tip_fn(sharechain_tip_fn_t fn) { m_sharechain_tip_fn = thread_safe_wrap(std::move(fn)); }

    // Sharechain delta callback — returns shares newer than given hash
    using sharechain_delta_fn_t = std::function<nlohmann::json(const std::string&)>;
    void set_sharechain_delta_fn(sharechain_delta_fn_t fn) {
        m_sharechain_delta_fn_raw = fn;   // raw copy for main-thread precompute
        m_sharechain_delta_fn = thread_safe_wrap(std::move(fn));
    }

    // Individual share lookup — returns full p2pool-compatible share JSON by hash
    using share_lookup_fn_t = std::function<nlohmann::json(const std::string&)>;
    void set_share_lookup_fn(share_lookup_fn_t fn) { m_share_lookup_fn = thread_safe_wrap(std::move(fn)); }

    // Network difficulty callback — invoked from refresh_work() with real value
    using network_difficulty_fn_t = std::function<void(double)>;
    void set_on_network_difficulty(network_difficulty_fn_t fn) { m_on_network_difficulty_fn = std::move(fn); }
    
    // Payout management methods
    nlohmann::json getpayoutinfo(const std::string& request_id = "");
    nlohmann::json getminerstats(const std::string& request_id = "");
    nlohmann::json setmessageblob(const std::string& message_blob_hex, const std::string& request_id = "");
    nlohmann::json getmessageblob(const std::string& request_id = "");
    void set_pool_payout_address(const std::string& address);
    void set_pool_fee_percent(double fee_percent);

    // V36-compatible probabilistic node fee: at share creation time,
    // with probability fee%, the share's payout address is replaced with
    // the node operator's address.  This flows through PPLNS naturally.
    void set_node_fee(double percent, const std::vector<unsigned char>& script) {
        m_node_fee_percent = percent;
        m_node_fee_script  = script;
        m_pool_fee_percent = percent;  // keep /fee endpoint in sync
    }
    // String-based overload: converts Base58Check address to P2PKH scriptPubKey
    void set_node_fee_from_address(double percent, const std::string& address);
    // Donation script used by get_expected_payouts (p2pool protocol)
    void set_donation_script(const std::vector<unsigned char>& script) {
        m_donation_script = script;
    }
    const std::vector<unsigned char>& get_donation_script() const { return m_donation_script; }
    // Cached share version (v35/v36) — updated by PPLNS hook from AutoRatchet
    void set_cached_share_version(int64_t v) { m_cached_share_version = v; }
    int64_t get_cached_share_version() const { return m_cached_share_version; }
    // Local stratum hashrate (H/s) — set via callback from WebServer
    void set_stratum_hashrate_fn(std::function<double()> fn) { m_stratum_hashrate_fn = thread_safe_wrap(std::move(fn)); }
    double get_stratum_total_hashrate() const { return m_stratum_hashrate_fn ? m_stratum_hashrate_fn() : 0.0; }

    // Pool hashrate (H/s) — from P2P node's get_pool_attempts_per_second
    void set_pool_hashrate_fn(std::function<double()> fn) { m_pool_hashrate_fn = thread_safe_wrap(std::move(fn)); }
    double get_pool_hashrate() const { return m_pool_hashrate_fn ? m_pool_hashrate_fn() : 0.0; }

    // Rate monitor stats for p2pool-style status (DOA%, time window)
    struct RateStats {
        double hashrate = 0;
        double effective_dt = 0;
        int total_datums = 0;
        int dead_datums = 0;
    };
    void set_stratum_rate_stats_fn(std::function<RateStats()> fn) { m_stratum_rate_stats_fn = thread_safe_wrap(std::move(fn)); }
    RateStats get_stratum_rate_stats() const { return m_stratum_rate_stats_fn ? m_stratum_rate_stats_fn() : RateStats{}; }

    // Current PPLNS outputs for payout display
    std::vector<std::pair<std::string, uint64_t>> get_cached_pplns_outputs() const {
        std::lock_guard<std::mutex> l(m_work_mutex);
        return m_cached_pplns_outputs;
    }
    // THE state root for sharechain anchoring (used by merged coinbase too)
    uint256 get_the_state_root() const { std::lock_guard<std::mutex> l(m_work_mutex); return m_cached_the_state_root; }
    // String-based overload for donation script
    void set_donation_script_from_address(const std::string& address);

    // Solo mining configuration
    void set_solo_mode(bool enabled) { m_solo_mode = enabled; }
    void set_solo_address(const std::string& address) { m_solo_address = address; }
    bool is_solo_mode() const { return m_solo_mode; }
    const std::string& get_solo_address() const { return m_solo_address; }

    // Payout system integration
    void set_payout_manager(c2pool::payout::PayoutManager* manager) { m_payout_manager_ptr = manager; }
    c2pool::payout::PayoutManager* get_payout_manager_ptr() const { return m_payout_manager_ptr; }

    // Wire a live coin-daemon RPC connection so getblocktemplate/submitblock use real data
    void set_coin_rpc(ltc::coin::NodeRPC* rpc, ltc::interfaces::Node* coin = nullptr);
    // Wire an embedded coin node (Phase 4) — used instead of RPC when set.
    // refresh_work() will call node->getwork(); block submissions relay via on_block_relay.
    void set_embedded_node(ltc::coin::CoinNodeInterface* node);
    // Fetch a fresh block template from the coin daemon and cache it
    void refresh_work();
    // Return the most recently cached block template (empty json if unavailable)
    nlohmann::json get_current_work_template() const;
    // Return Stratum-ready merkle branch hashes
    std::vector<std::string> get_stratum_merkle_branches() const;
    // Return coinb1 and coinb2 (coinbase parts split around extranonce)
    std::pair<std::string, std::string> get_coinbase_parts() const;

    // Return whether segwit is active in the current template
    bool get_segwit_active() const;
    // Return the cached MWEB extension data (empty if none)
    std::string get_cached_mweb() const;
    // Return the P2Pool witness commitment hex (computed in refresh_work)
    std::string get_cached_witness_commitment() const;
    // Return the raw wtxid merkle root (computed in refresh_work)
    uint256 get_cached_witness_root() const;

    WorkSnapshot get_work_snapshot() const;

    // Returns current GBT previousblockhash (for stale block template detection)
    std::string get_current_gbt_prevhash() const;

    // Found block status and record (Layer +2 — blockchain-accepted blocks)
    enum class BlockStatus : uint8_t {
        pending   = 0,  // submitted, awaiting confirmation
        confirmed = 1,  // in best chain (confirmations > 0)
        orphaned  = 2,  // replaced by another block at same height
        stale     = 3,  // submitted with stale prev_block
    };
    struct FoundBlock {
        uint64_t    height;
        std::string hash;
        uint64_t    ts;
        BlockStatus status{BlockStatus::pending};
        uint8_t     check_count{0};   // how many verification attempts
        std::string chain;            // "LTC"/"tLTC"/"DOGE" etc — for log display
        uint32_t    confirmations{0}; // last known confirmation count
        // Dashboard-enriched fields (populated at record time)
        std::string miner;                 // payout address of the share that found the block
        std::string share_hash;            // share hash that produced the block
        double      network_difficulty{0}; // network difficulty at time of find
        double      share_difficulty{0};   // share difficulty at time of find
        double      pool_hashrate{0};      // pool hashrate at time of find
        uint64_t    subsidy{0};            // block reward in satoshis
        double      expected_time{0};      // expected seconds to find at current rate
        double      time_to_find{0};       // actual seconds since previous block
        double      luck{0};              // expected_time / time_to_find * 100
    };

    // Block acceptance verification: schedule async checks at +10s, +30s, +120s.
    // The verify callback returns: >0=confirmed, <0=orphaned, 0=pending.
    using block_verify_fn_t = std::function<int(const std::string& hash)>;
    using block_store_fn_t = std::function<bool(const FoundBlock& blk)>;
    using block_load_fn_t  = std::function<std::vector<FoundBlock>()>;
    void set_block_verify_fn(block_verify_fn_t fn);
    void set_io_context(boost::asio::io_context* ctx) { m_context = ctx;
        m_main_thread_id = std::this_thread::get_id();
        LOG_INFO << "MiningInterface::set_io_context this=" << this << " ctx=" << ctx; }

    /// Thread-safe cached callback entry.  Main thread computes + publishes;
    /// HTTP thread reads a shared_ptr snapshot (lock-free, zero contention).
    template<typename R>
    struct CacheEntry {
        std::function<R()> fn;
        std::atomic<std::shared_ptr<const R>> cached{std::make_shared<const R>()};

        explicit CacheEntry(std::function<R()> f) : fn(std::move(f)) {}

        R refresh() {
            auto result = std::make_shared<const R>(fn());
            cached.store(result, std::memory_order_release);
            return *result;
        }

        R get() const {
            auto snap = cached.load(std::memory_order_acquire);
            return *snap;
        }
    };

    /// Zero-arg overload: RCU cache pattern.
    /// Main thread calls → computes result, updates cache, returns result.
    /// HTTP thread calls → returns cached result instantly (zero blocking).
    /// Cache is also refreshed periodically via refresh_http_caches().
    template<typename R>
    std::function<R()> thread_safe_wrap(std::function<R()> fn) {
        if (!fn) return fn;
        auto entry = std::make_shared<CacheEntry<R>>(fn);
        m_cache_refresh_fns.push_back([entry]() { entry->refresh(); });
        return [this, entry, fn = std::move(fn)]() -> R {
            if (!m_context || std::this_thread::get_id() == m_main_thread_id) {
                return entry->refresh();   // main thread: compute + cache
            }
            return entry->get();           // HTTP thread: instant cached read
        };
    }

    /// Parameterized overload: dispatch-and-wait (used for delta, lookup, etc.)
    /// These are called less frequently so blocking is acceptable.
    template<typename R, typename Arg0, typename... Args>
    std::function<R(Arg0, Args...)> thread_safe_wrap(std::function<R(Arg0, Args...)> fn) {
        if (!fn) return fn;
        return [this, fn = std::move(fn)](Arg0 arg0, Args... args) -> R {
            if (!m_context || std::this_thread::get_id() == m_main_thread_id) {
                return fn(arg0, args...);
            }
            std::promise<R> prom;
            auto fut = prom.get_future();
            boost::asio::post(*m_context, [&]() {
                try {
                    prom.set_value(fn(arg0, args...));
                } catch (...) {
                    prom.set_exception(std::current_exception());
                }
            });
            return fut.get();
        };
    }

    /// Void-returning overload (parameterized)
    template<typename... Args>
    std::function<void(Args...)> thread_safe_wrap(std::function<void(Args...)> fn) {
        if (!fn) return fn;
        return [this, fn = std::move(fn)](Args... args) {
            if (!m_context || std::this_thread::get_id() == m_main_thread_id) {
                fn(args...);
                return;
            }
            std::promise<void> prom;
            auto fut = prom.get_future();
            boost::asio::post(*m_context, [&]() {
                try {
                    fn(args...);
                    prom.set_value();
                } catch (...) {
                    prom.set_exception(std::current_exception());
                }
            });
            fut.get();
        };
    }

    /// Refresh all zero-arg callback caches.  Call from main thread periodically.
    void refresh_http_caches() {
        for (auto& fn : m_cache_refresh_fns) {
            try { fn(); } catch (...) {}
        }
    }
    void schedule_block_verification(const std::string& block_hash);

    // Per-chain verify function: register additional verifiers for merged chains
    void add_chain_verify_fn(const std::string& chain, block_verify_fn_t fn);

    /// Read-only access to found blocks (for sharechain window grid).
    std::vector<FoundBlock> get_found_blocks() const {
        std::lock_guard<std::mutex> lock(m_blocks_mutex);
        return m_found_blocks;
    }

    /// Set persistence callbacks for found blocks (Layer +2).
    void set_found_block_persistence(block_store_fn_t persist_fn, block_load_fn_t load_fn);

    /// Load persisted found blocks from storage (call once after persistence is set)
    void load_persisted_found_blocks();

    /// Backfill network_difficulty on loaded blocks using a block hash → difficulty lookup.
    /// Called after embedded header chain is available.
    using block_diff_lookup_fn = std::function<double(const std::string& block_hash)>;
    using block_ts_lookup_fn = std::function<uint32_t(const std::string& block_hash)>;
    void backfill_block_fields(block_diff_lookup_fn diff_fn, block_ts_lookup_fn ts_fn);

    /// Merged block persistence — opaque store pointer, cast in .cpp.
    void set_merged_block_store(std::shared_ptr<void> store);
    std::shared_ptr<void> get_merged_block_store() const { return m_merged_block_store; }

    /// Coin P2P peer info callbacks (daemon-style getpeerinfo).
    using coin_peer_info_fn = std::function<nlohmann::json()>;
    void set_ltc_peer_info_fn(coin_peer_info_fn fn) { m_ltc_peer_info_fn = thread_safe_wrap(std::move(fn)); }
    void set_doge_peer_info_fn(coin_peer_info_fn fn) { m_doge_peer_info_fn = thread_safe_wrap(std::move(fn)); }

    // Callback fired whenever a block submission is attempted.
    // Arguments: header hex (first 80 bytes), stale_info (none=accepted, orphan=stale prev, doa=daemon rejected).
    void set_on_block_submitted(std::function<void(const std::string& header_hex, int stale_info)> fn);

    // Callback for P2P block relay — receives full block hex for direct daemon P2P broadcast.
    void set_on_block_relay(std::function<void(const std::string& full_block_hex)> fn);
    // Optional RPC submitblock fallback for embedded mode (returns error string, empty = ok).
    void set_rpc_submit_fallback(std::function<std::string(const std::string&)> fn);
    // Redistribute / address-fallback callback.
    // Called when a share's primary address cannot be resolved to a valid hash160.
    // Receives the bad address string; must return a 40-char hex hash160, or "" to keep share.
    using address_fallback_fn_t = std::function<std::string(const std::string&)>;
    void set_address_fallback_fn(address_fallback_fn_t fn) { m_address_fallback_fn = std::move(fn); }

    // Return true if the merged-mining manager has a configured chain with chain_id.
    bool has_merged_chain(uint32_t chain_id) const;

    // Extract the 40-char hex hash160 from the node fee scriptPubKey (P2PKH bytes 3-22).
    // Returns "" if the fee script is not a 25-byte P2PKH.
    std::string get_node_fee_hash160() const;
private:
    void setup_methods();
    // Build Stratum-compatible coinb1/coinb2 from a live block template
    // Output ordering matches generate_share_transaction():
    //   segwit_commitment(first) → PPLNS payouts → donation → OP_RETURN(last)
    /// Compute THE state root: Merkle(L-1, L0_pplns, L+1, epoch_meta).
    /// L-1 and L+1 are zero (placeholders until THE activates).
    /// L0 = SHA256d of sorted PPLNS output table. Epoch = SHA256d of metadata.
    static uint256 compute_the_state_root(
        const std::vector<std::pair<std::string,uint64_t>>& pplns_outputs,
        uint32_t chain_length, uint32_t block_height, uint32_t bits);

    static std::pair<std::string, std::string> build_coinbase_parts(
        const nlohmann::json& tmpl, uint64_t coinbase_value,
        const std::vector<std::pair<std::string,uint64_t>>& outputs,
        bool raw_scripts = false,
        const std::vector<uint8_t>& mm_commitment = {},
        const std::string& witness_commitment_hex = {},
        const std::string& ref_hash_hex = {},
        const uint256& the_state_root = uint256(),
        const std::string& coinbase_text = {});
    // Compute Stratum merkle branches from a list of tx hashes (excl. coinbase)
    static std::vector<std::string> compute_merkle_branches(std::vector<std::string> tx_hashes);
    // Reconstruct merkle root from coinbase hex + Stratum merkle branches
    static uint256 reconstruct_merkle_root(const std::string& coinbase_hex,
                                           const std::vector<std::string>& merkle_branches);
    // Build full block hex from Stratum submit parameters.
    // When job is provided, uses its frozen template data instead of the live m_cached_template.
    std::string build_block_from_stratum(const std::string& extranonce1,
                                         const std::string& extranonce2,
                                         const std::string& ntime,
                                         const std::string& nonce,
                                         const JobSnapshot* job = nullptr) const;

    // Try submitting to merged-mined aux chains if their target is met
    // Returns true if a merged block was found (for twin block detection)
    bool check_merged_mining(const std::string& block_hex,
                             const std::string& extranonce1,
                             const std::string& extranonce2,
                             const JobSnapshot* job = nullptr);
    
    // Internal state
    uint64_t m_work_id_counter;
    std::map<std::string, nlohmann::json> m_active_work;
    std::unique_ptr<LitecoinRpcClient> m_rpc_client;
    bool m_testnet;  // Store testnet flag
    Blockchain m_blockchain;  // Store blockchain type
    std::shared_ptr<IMiningNode> m_node;  // Connection to c2pool node for difficulty tracking
    BlockchainAddressValidator m_address_validator;  // New address validator
    std::unique_ptr<c2pool::payout::PayoutManager> m_payout_manager;  // Payout management
    
    // Solo mining configuration
    bool m_solo_mode = false;
    std::string m_solo_address;
    
    // Payout system integration
    c2pool::payout::PayoutManager* m_payout_manager_ptr = nullptr;

    // Real coin daemon connection (replaces mock LitecoinRpcClient)
    ltc::coin::NodeRPC*          m_coin_rpc       = nullptr;
    ltc::interfaces::Node*       m_coin_node      = nullptr;
    // Phase 4: embedded coin node (preferred over RPC when set)
    ltc::coin::CoinNodeInterface* m_embedded_node = nullptr;
    // io_context for scheduling async verification timers
    boost::asio::io_context*     m_context        = nullptr;
    std::thread::id              m_main_thread_id;          // set by set_io_context()
    std::vector<std::function<void()>> m_cache_refresh_fns; // populated by thread_safe_wrap
    std::atomic<bool>       m_work_valid{false};
    std::atomic<uint64_t>   m_work_generation{0};       // incremented on each refresh_work()
    std::atomic<int64_t>    m_last_work_update_time{0}; // monotonic seconds since epoch
    nlohmann::json          m_cached_template;

public:
    // Monotonically increasing counter — incremented on each refresh_work().
    // Used by per-miner safety timer to avoid pushing unchanged work.
    uint64_t get_work_generation() const { return m_work_generation.load(); }

    // Share target from compute_share_target() — set by ref_hash_fn, used by
    // mining.notify (nbits) and share creation (params.bits).
    // These are consensus-level share difficulty, NOT the block difficulty.
    std::atomic<uint32_t>   m_share_bits{0};
    std::atomic<uint32_t>   m_share_max_bits{0};
private:
    std::vector<std::string> m_cached_merkle_branches;   // Stratum merkle branches
    std::string             m_cached_coinb1;
    std::string             m_cached_coinb2;
    mutable std::mutex      m_work_mutex;

    // Block-found callback (header_hex, stale_info: 0=none, 253=orphan, 254=doa)
    std::function<void(const std::string&, int)> m_on_block_submitted;

    find_peer_prev_fn_t m_find_peer_prev_fn;

    // P2P block relay callback — receives the full block hex for direct P2P broadcast.
    // Only called for accepted blocks (not stale/orphan/doa).
    std::function<void(const std::string&)> m_on_block_relay;

    // Optional RPC submitblock fallback — called BEFORE P2P relay in embedded mode.
    // Returns the error string from litecoind (empty = accepted).
    std::function<std::string(const std::string&)> m_rpc_submit_fallback;

    // Share tracker hook
    std::function<uint256()> m_best_share_hash_fn;

    // Sharechain stats callback
    sharechain_stats_fn_t m_sharechain_stats_fn;
    sharechain_window_fn_t m_sharechain_window_fn;
    sharechain_tip_fn_t m_sharechain_tip_fn;
    sharechain_delta_fn_t m_sharechain_delta_fn;
    sharechain_delta_fn_t m_sharechain_delta_fn_raw;  // unwrapped, for main-thread precompute
    share_lookup_fn_t m_share_lookup_fn;

public:
    // ── Sharechain window response cache (Layer 1 + 2) ──
    void invalidate_window_cache() {
        std::lock_guard<std::mutex> lock(m_window_cache_mutex);
        m_window_cache_etag.clear();
    }
    // ── Pre-computed delta cache (called from main thread on new share) ──
    void precompute_delta(const std::string& prev_tip_hash);

    // ── Per-share PPLNS cache ──
    void cache_pplns_at_tip();
    nlohmann::json get_pplns_for_tip(const std::string& tip_hash);
    // Background pre-computation: walks all verified shares after sync
    void start_pplns_precompute();
    bool pplns_precompute_done() const { return m_pplns_precompute_done.load(); }
    // ── Per-IP rate limiting (Layer 3) ──
    bool rate_check(const std::string& ip, int max_per_min);
    // ── SSE subscribers (Layer 4) ──
    void sse_push(const std::string& event_data);
    void sse_register(std::shared_ptr<tcp::socket> socket);
    size_t sse_subscriber_count() const;
private:
    std::mutex m_window_cache_mutex;
    std::string m_window_cache_json;
    std::string m_window_cache_etag;
    // Single-entry delta cache: pre-computed on main thread when tip changes.
    // SSE clients all request the same since_hash (previous tip) → ~100% hit rate.
    mutable std::mutex m_delta_cache_mutex;
    std::string m_delta_cache_since;         // since_hash this delta was computed for
    nlohmann::json m_delta_cache_result;     // the cached delta JSON
    struct RateBucket {
        int tokens{0};
        std::chrono::steady_clock::time_point last_refill;
    };
    std::mutex m_rate_mutex;
    std::unordered_map<std::string, RateBucket> m_rate_buckets;
    // Per-share PPLNS snapshots: share_short_hash → {addr: amount}
    std::mutex m_pplns_cache_mutex;
    std::unordered_map<std::string, nlohmann::json> m_pplns_per_tip;
    std::atomic<bool> m_pplns_precompute_done{false};
    // Cached full merged payouts (LTC + DOGE) — updated by cache_pplns_at_tip()
    mutable std::mutex m_merged_payouts_mutex;
    nlohmann::json m_cached_merged_payouts;
    std::thread m_pplns_precompute_thread;
    struct SSESubscriber {
        std::shared_ptr<tcp::socket> socket;
        std::string last_tip;
    };
    std::mutex m_sse_mutex;
    std::vector<SSESubscriber> m_sse_subscribers;

    // PPLNS computation hook
    pplns_fn_t m_pplns_fn;

    // Ref hash computation hook (per-connection work generation)
    ref_hash_fn_t m_ref_hash_fn;

    // Cached PPLNS outputs for per-connection coinbase generation
    // (populated in refresh_work, consumed in build_connection_coinbase)
    // m_cached_pplns_best_share records which share the PPLNS was computed from.
    // If build_connection_coinbase's frozen_prev_share differs, PPLNS is recomputed.
    std::vector<std::pair<std::string, uint64_t>> m_cached_pplns_outputs;
    uint256 m_cached_pplns_best_share;
    bool m_cached_raw_scripts{false};
    int64_t m_cached_share_version{36};  // V35/V36 PPLNS selection
    std::string m_cached_witness_commitment;
    uint256 m_cached_witness_root;  // raw wtxid merkle root
    std::vector<uint8_t> m_cached_mm_commitment;
    mutable std::vector<CachedMergedHeaderInfo> m_last_merged_header_infos;
    uint256 m_cached_the_state_root;  // THE state root for sharechain anchoring
    std::string m_cached_mweb;  // MWEB extension data from GBT (Litecoin)

    // Share creation hook
    create_share_fn_t m_create_share_fn;

    // Protocol message extraction hook for API display.
    protocol_messages_fn_t m_protocol_messages_fn;

    // Operator blob injected into locally created shares (thread-safe).
    mutable std::mutex m_message_blob_mutex;
    std::vector<unsigned char> m_operator_message_blob;

    // Cached transition messages loaded from blob files at startup.
    nlohmann::json m_cached_transition_message;        // null or {msg,url,urgency,...}
    nlohmann::json m_cached_authority_announcements;   // array of announcements

    // Coinbase scriptSig customization
    std::string m_coinbase_text;  // empty = "/c2pool/" default tag

    // Cached THE state for checkpoint creation (state_root already at line 639)
    uint32_t m_cached_sharechain_height{0};
    uint16_t m_cached_miner_count{0};
    double m_cached_pool_hashrate{0};
    std::function<double()> m_pool_hashrate_fn;

    // THE checkpoint callbacks (set by node layer)
    checkpoint_store_fn_t m_checkpoint_latest_fn;
    checkpoints_all_fn_t m_checkpoints_all_fn;
    checkpoint_verify_fn_t m_checkpoint_verify_fn;

    // Called when a block is found — creates a THE checkpoint
    checkpoint_create_fn_t m_checkpoint_create_fn;

    // Segwit activation (from template rules)
    bool m_segwit_active{false};

    // Integrated merged mining manager (non-owning)
    c2pool::merged::MergedMiningManager* m_mm_manager{nullptr};

    // Network difficulty callback
    network_difficulty_fn_t m_on_network_difficulty_fn;

    // Pool fee percent (set via set_pool_fee_percent)
    double m_pool_fee_percent{0.0};

    // V36 probabilistic node fee
    double m_node_fee_percent{0.0};
    std::vector<unsigned char> m_node_fee_script;   // node operator scriptPubKey
    std::string m_node_fee_address;                 // node operator address (display/logging)
    std::vector<unsigned char> m_donation_script;   // protocol donation scriptPubKey
    std::function<double()> m_stratum_hashrate_fn;  // callback to get stratum total hashrate
    std::function<RateStats()> m_stratum_rate_stats_fn;  // callback to get rate monitor stats

    // Cached network difficulty (computed from bits in refresh_work)
    std::atomic<double> m_network_difficulty{0.0};

    // Found block list (persistent via Layer +2 callbacks)
    std::vector<FoundBlock> m_found_blocks;   // newest first, no cap (persistent)
    mutable std::mutex      m_blocks_mutex;

    // Persistent found block storage (Layer +2) — functional callbacks
    block_store_fn_t m_persist_block_fn;   // called on record + status change
    block_load_fn_t  m_load_blocks_fn;     // called on startup

    std::shared_ptr<void> m_merged_block_store;  // MergedBlockStore (opaque)
    coin_peer_info_fn m_ltc_peer_info_fn;
    coin_peer_info_fn m_doge_peer_info_fn;
    block_verify_fn_t m_block_verify_fn;  // default (parent chain)
    std::map<std::string, block_verify_fn_t> m_chain_verify_fns; // per-chain
    void verify_found_block(size_t index);

    // Pool start time for /uptime
    std::chrono::steady_clock::time_point m_start_time{std::chrono::steady_clock::now()};

    // Stratum tuning (shared with all StratumSessions via pointer)
    StratumConfig m_stratum_config;
    std::string m_cors_origin;  // empty = no CORS header; set explicitly if needed
    std::string m_auth_token;   // auth token for sensitive endpoints; empty = no auth
public:
    void set_stratum_config(const StratumConfig& cfg) { m_stratum_config = cfg; }
    const StratumConfig& get_stratum_config() const { return m_stratum_config; }
    void set_cors_origin(const std::string& origin) { m_cors_origin = origin; }
    const std::string& get_cors_origin() const { return m_cors_origin; }

    // Authentication token for sensitive endpoints (/control/*, /web/log, /logs/export)
    // Empty = no auth required (NOT recommended for production)
    void set_auth_token(const std::string& token) { m_auth_token = token; }
    bool verify_auth_token(const std::string& token) const {
        return !m_auth_token.empty() && token == m_auth_token;
    }
    bool auth_required() const { return !m_auth_token.empty(); }

    // Dashboard static file serving directory
    void set_dashboard_dir(const std::string& dir) { m_dashboard_dir = dir; }
    const std::string& get_dashboard_dir() const { return m_dashboard_dir; }

    // Google Analytics (or compatible) measurement ID injected into HTML pages
    void set_analytics_id(const std::string& id) { m_analytics_id = id; }
    const std::string& get_analytics_id() const { return m_analytics_id; }

    // Custom external block explorer link prefixes (overrides defaults)
    void set_custom_explorer_links(const std::string& addr, const std::string& block, const std::string& tx) {
        m_custom_address_explorer = addr;
        m_custom_block_explorer = block;
        m_custom_tx_explorer = tx;
    }

    // Explorer API
    using explorer_chaininfo_fn_t = std::function<nlohmann::json(const std::string& chain)>;
    using explorer_blockhash_fn_t = std::function<std::string(uint32_t height, const std::string& chain)>;
    using explorer_getblock_fn_t  = std::function<nlohmann::json(const std::string& hash, const std::string& chain)>;
    void set_explorer_enabled(bool enabled) { m_explorer_enabled = enabled; }
    bool is_explorer_enabled() const { return m_explorer_enabled; }
    void set_explorer_url(const std::string& url) { m_explorer_url = url; }
    const std::string& get_explorer_url() const { return m_explorer_url; }
    void set_explorer_chaininfo_fn(explorer_chaininfo_fn_t fn) { m_explorer_chaininfo_fn = thread_safe_wrap(std::move(fn)); }
    void set_explorer_blockhash_fn(explorer_blockhash_fn_t fn) { m_explorer_blockhash_fn = thread_safe_wrap(std::move(fn)); }
    void set_explorer_getblock_fn(explorer_getblock_fn_t fn) { m_explorer_getblock_fn = thread_safe_wrap(std::move(fn)); }
    bool has_explorer_chaininfo_fn() const { return !!m_explorer_chaininfo_fn; }
    bool has_explorer_blockhash_fn() const { return !!m_explorer_blockhash_fn; }
    bool has_explorer_getblock_fn() const { return !!m_explorer_getblock_fn; }
    nlohmann::json call_explorer_chaininfo(const std::string& c) { return m_explorer_chaininfo_fn(c); }
    std::string call_explorer_blockhash(uint32_t h, const std::string& c) { return m_explorer_blockhash_fn(h, c); }
    nlohmann::json call_explorer_getblock(const std::string& h, const std::string& c) { return m_explorer_getblock_fn(h, c); }

    // Mempool explorer callbacks
    using explorer_mempoolinfo_fn_t  = std::function<nlohmann::json(const std::string& chain)>;
    using explorer_rawmempool_fn_t   = std::function<nlohmann::json(const std::string& chain, bool verbose, uint32_t limit)>;
    using explorer_mempoolentry_fn_t = std::function<nlohmann::json(const std::string& txid, const std::string& chain)>;
    void set_explorer_mempoolinfo_fn(explorer_mempoolinfo_fn_t fn) { m_explorer_mempoolinfo_fn = thread_safe_wrap(std::move(fn)); }
    void set_explorer_rawmempool_fn(explorer_rawmempool_fn_t fn) { m_explorer_rawmempool_fn = thread_safe_wrap(std::move(fn)); }
    void set_explorer_mempoolentry_fn(explorer_mempoolentry_fn_t fn) { m_explorer_mempoolentry_fn = thread_safe_wrap(std::move(fn)); }
    bool has_explorer_mempoolinfo_fn() const { return !!m_explorer_mempoolinfo_fn; }
    bool has_explorer_rawmempool_fn() const { return !!m_explorer_rawmempool_fn; }
    bool has_explorer_mempoolentry_fn() const { return !!m_explorer_mempoolentry_fn; }
    nlohmann::json call_explorer_mempoolinfo(const std::string& c) { return m_explorer_mempoolinfo_fn(c); }
    nlohmann::json call_explorer_rawmempool(const std::string& c, bool v, uint32_t l) { return m_explorer_rawmempool_fn(c, v, l); }
    nlohmann::json call_explorer_mempoolentry(const std::string& t, const std::string& c) { return m_explorer_mempoolentry_fn(t, c); }

    // Primary payout address (for legacy /payout_addr endpoint)
    void set_payout_address(const std::string& addr) { m_payout_address = addr; }
    const std::string& get_payout_address() const { return m_payout_address; }

    // P2P peer info callback — returns JSON array of peer objects [{address,version,incoming,uptime,txpool_size}]
    using peer_info_fn_t = std::function<nlohmann::json()>;
    void set_peer_info_fn(peer_info_fn_t fn) { m_peer_info_fn = thread_safe_wrap(std::move(fn)); }

    // Port configuration for /node_info
    void set_p2p_port(uint16_t port) { m_p2p_port = port; }
    void set_worker_port(uint16_t port) { m_worker_port = port; }
    void set_external_ip(const std::string& ip) { m_external_ip = ip; }
    void set_pool_version(const std::string& ver) { m_pool_version = ver; }

    // Best share difficulty tracking (for /best_share, /miner_stats)
    void record_share_difficulty(double difficulty, const std::string& miner);
    void record_merged_share_difficulty(double difficulty, const std::string& miner);

    // Stat log entry (appended every 5 minutes, rolling 24h window for /web/log JSON)
    void update_stat_log();
private:

    // Lightweight runtime state for MVP mining controls.
    bool m_mining_enabled{true};
    std::set<std::string> m_banned_targets;
    mutable std::mutex m_control_mutex;

    // Fallback address resolver for invalid/empty miner addresses (redistribute / DOGE→LTC)
    address_fallback_fn_t m_address_fallback_fn;

    // Dashboard static file serving directory (empty = disabled)
    std::string m_dashboard_dir;
    // Google Analytics measurement ID (e.g. "G-XXXXXXXXXX")
    std::string m_analytics_id;
    // Custom external block explorer link prefixes (empty = use Blockchair defaults)
    std::string m_custom_address_explorer;
    std::string m_custom_block_explorer;
    std::string m_custom_tx_explorer;
    // Explorer configuration
    bool m_explorer_enabled{false};
    std::string m_explorer_url;  // URL for dashboard nav link injection
    // Explorer data callbacks (set by c2pool_refactored.cpp)
    explorer_chaininfo_fn_t m_explorer_chaininfo_fn;
    explorer_blockhash_fn_t m_explorer_blockhash_fn;
    explorer_getblock_fn_t  m_explorer_getblock_fn;
    // Mempool explorer callbacks
    explorer_mempoolinfo_fn_t  m_explorer_mempoolinfo_fn;
    explorer_rawmempool_fn_t   m_explorer_rawmempool_fn;
    explorer_mempoolentry_fn_t m_explorer_mempoolentry_fn;
    // Primary payout address for legacy API
    std::string m_payout_address;

    // P2P peer info callback
    peer_info_fn_t m_peer_info_fn;

    // Port configuration
    uint16_t m_p2p_port{9338};
    uint16_t m_worker_port{9327};
    std::string m_external_ip;
    std::string m_pool_version{"c2pool/0.12.0"};

    // Best share difficulty tracking
    struct BestDifficulty {
        double all_time{0.0};
        std::string all_time_miner;
        uint64_t all_time_ts{0};
        double session{0.0};
        std::string session_miner;
        uint64_t session_ts{0};
        double round{0.0};
        std::string miner;       // round-level miner (backward compat)
        uint64_t timestamp{0};   // round-level timestamp (backward compat)
        uint64_t round_start{0};
        // Merged chain (DOGE) best share tracking
        double merged_all_time{0.0};
        std::string merged_all_time_miner;
        uint64_t merged_all_time_ts{0};
        double merged_round{0.0};
        std::string merged_round_miner;
        uint64_t merged_round_ts{0};
        uint64_t merged_round_start{0};
    };
    BestDifficulty m_best_difficulty;
    mutable std::mutex m_best_diff_mutex;

    // Stat log for /web/log JSON endpoint (rolling 24h window)
    struct StatLogEntry {
        double time;
        double pool_hash_rate;
        double pool_stale_prop;
        nlohmann::json local_hash_rates;       // {addr: hashrate}
        nlohmann::json local_dead_hash_rates;  // {addr: dead_hashrate}
        int worker_count{0};              // unique address.worker combos
        int miner_count{0};               // unique base addresses
        int connected_count{0};           // raw stratum TCP connections
        uint64_t shares;
        uint64_t stale_shares;
        double current_payout;
        nlohmann::json current_payouts;   // {addr: payout_float}
        nlohmann::json peers;             // {incoming: N, outgoing: N}
        nlohmann::json desired_versions;  // {version_str: hashrate}
        double attempts_to_share;
        double attempts_to_block;
        double block_value;
        double memory_usage{0};           // RSS in bytes
    };
    std::vector<StatLogEntry> m_stat_log;
    mutable std::mutex m_stat_log_mutex;

    // Network difficulty history for /network_difficulty
    struct NetDiffSample { double ts; double difficulty; std::string source; };
    std::vector<NetDiffSample> m_netdiff_history;  // oldest-first, capped at 2000
    mutable std::mutex m_netdiff_mutex;
    double m_last_netdiff_sampled{0.0};  // dedup: skip if unchanged
    void add_netdiff_sample(double difficulty, const std::string& source);

    // ── Stratum worker session tracking ──────────────────────────────────
public:
    struct WorkerInfo {
        std::string username;      // miner address (after parsing)
        std::string worker_name;   // worker suffix from "ADDRESS.worker" (e.g. "alpha")
        double hashrate{0.0};      // measured H/s from HashrateTracker
        double dead_hashrate{0.0}; // DOA H/s
        double difficulty{1.0};    // current vardiff difficulty
        uint64_t accepted{0};
        uint64_t rejected{0};
        uint64_t stale{0};
        std::chrono::steady_clock::time_point connected_at;
        std::string remote_endpoint;  // "ip:port"
    };

    void register_stratum_worker(const std::string& session_id, const WorkerInfo& info);
    void unregister_stratum_worker(const std::string& session_id);
    void update_stratum_worker(const std::string& session_id,
                               double hashrate, double dead_hashrate, double difficulty,
                               uint64_t accepted, uint64_t rejected, uint64_t stale);
    std::map<std::string, WorkerInfo> get_stratum_workers() const;

private:
    std::map<std::string, WorkerInfo> m_stratum_workers;
    mutable std::mutex m_stratum_workers_mutex;
    std::chrono::steady_clock::time_point m_stratum_start_time{std::chrono::steady_clock::now()};
};

/// Main Web Server class
class WebServer
{
    net::io_context& ioc_;               // Main event loop (Stratum, timers, mining)
    net::io_context http_ioc_;           // Dedicated HTTP event loop (dashboard/REST)
    std::thread http_thread_;            // Thread driving http_ioc_
    tcp::acceptor acceptor_;
    std::shared_ptr<MiningInterface> mining_interface_;
    std::string bind_address_;
    uint16_t port_;
    uint16_t stratum_port_;  // Explicit Stratum port configuration
    bool running_;
    bool testnet_;
    Blockchain blockchain_;
    std::thread server_thread_;
    std::unique_ptr<StratumServer> stratum_server_;

    // Solo mining configuration
    bool solo_mode_;
    std::string solo_address_;

    // Debounce timer for trigger_work_refresh_debounced()
    std::shared_ptr<net::steady_timer> m_work_refresh_timer;
    bool m_work_refresh_pending = false;

    // Payout system integration
    c2pool::payout::PayoutManager* payout_manager_ptr_ = nullptr;

    // Optional coin daemon RPC (enables real getblocktemplate + submitblock)
    ltc::coin::NodeRPC*    m_coin_rpc_  = nullptr;
    ltc::interfaces::Node* m_coin_node_ = nullptr;
    
public:
    WebServer(net::io_context& ioc, const std::string& address, uint16_t port, bool testnet = false);
    WebServer(net::io_context& ioc, const std::string& address, uint16_t port, bool testnet, std::shared_ptr<IMiningNode> node);
    WebServer(net::io_context& ioc, const std::string& address, uint16_t port, bool testnet, std::shared_ptr<IMiningNode> node, Blockchain blockchain);
    ~WebServer();

    // Start/stop the server
    bool start();
    bool start_solo();  // Start in solo mining mode (Stratum only)
    void stop();
    
    // Solo mining configuration
    void set_solo_mode(bool enabled) { solo_mode_ = enabled; }
    void set_solo_address(const std::string& address) { solo_address_ = address; }
    bool is_solo_mode() const { return solo_mode_; }
    const std::string& get_solo_address() const { return solo_address_; }

    // Payout system integration
    void set_payout_manager(c2pool::payout::PayoutManager* manager) { payout_manager_ptr_ = manager; }
    c2pool::payout::PayoutManager* get_payout_manager_ptr() const { return payout_manager_ptr_; }

    /// Per-address hashrate aggregation from stratum.
    /// Matches p2pool: get_local_addr_rates() (work.py:1975-1990).
    /// Returns {pubkey_hash → hashrate (H/s)} for all connected miners.
    std::map<std::array<uint8_t, 20>, double> get_local_addr_rates() const;

    // Stratum server control methods
    bool start_stratum_server();
    void stop_stratum_server();
    bool is_stratum_running() const;
    void set_stratum_port(uint16_t port);
    uint16_t get_stratum_port() const;

    // Dashboard directory for static file serving
    void set_dashboard_dir(const std::string& dir);
    void set_analytics_id(const std::string& id);

    // Explorer API — forward to MiningInterface
    void set_explorer_enabled(bool enabled);
    void set_explorer_url(const std::string& url);

    // Wire a live coin-daemon RPC connection for block template generation
    void set_coin_rpc(ltc::coin::NodeRPC* rpc, ltc::interfaces::Node* coin = nullptr);
    // Wire an embedded coin node (Phase 4 — preferred over RPC when set)
    void set_embedded_node(ltc::coin::CoinNodeInterface* node);
    // Forward block-found callback to the underlying MiningInterface
    void set_on_block_submitted(std::function<void(const std::string&, int)> fn);
    // Forward P2P block relay callback to the underlying MiningInterface
    void set_on_block_relay(std::function<void(const std::string&)> fn);
    // Immediately refresh the cached block template and push to all miners.
    // Use for time-critical events (new LTC block).
    void trigger_work_refresh();
    // Debounced variant: coalesces rapid-fire calls (share arrivals) into one
    // refresh after 100ms. Matches p2pool's Twisted reactor tick coalescing.
    void trigger_work_refresh_debounced();
    // Wire the share tracker's best hash into MiningInterface
    void set_best_share_hash_fn(std::function<uint256()> fn);
    // Wire the PPLNS computation from the share tracker
    void set_pplns_fn(MiningInterface::pplns_fn_t fn);
    // Set the integrated merged mining manager
    void set_merged_mining_manager(c2pool::merged::MergedMiningManager* mgr);

    // Access the underlying MiningInterface (e.g. for record_found_block)
    MiningInterface* get_mining_interface() const { return mining_interface_.get(); }

private:
    void accept_connections();
    void handle_accept(beast::error_code ec, tcp::socket socket);
};

// StratumSession and StratumServer — see stratum_server.hpp

} // namespace core
