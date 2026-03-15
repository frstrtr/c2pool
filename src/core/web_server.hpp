#pragma once

#include <memory>
#include <string>
#include <functional>
#include <thread>
#include <atomic>
#include <mutex>
#include <set>
#include <map>
#include <unordered_map>
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
    double min_difficulty       = 0.001;    // floor for per-connection vardiff
    double max_difficulty       = 65536.0;  // ceiling for per-connection vardiff
    double target_time          = 10.0;     // seconds between pseudoshares
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

    // Monitoring endpoints for Qt control panel
    nlohmann::json rest_uptime();
    nlohmann::json rest_connected_miners();
    nlohmann::json rest_stratum_stats();
    nlohmann::json rest_global_stats();
    nlohmann::json rest_sharechain_stats();
    nlohmann::json rest_sharechain_window();
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
    nlohmann::json rest_version_signaling();         // /version_signaling — V36 version tracking
    nlohmann::json rest_v36_status();                // /v36_status — V36 diagnostic
    nlohmann::json rest_patron_sendmany(const std::string& total); // /patron_sendmany/<total> — sendmany text
    nlohmann::json rest_tracker_debug();             // /tracker_debug — debug sharechain info

    // Merged mining endpoints
    nlohmann::json rest_merged_stats();              // /merged_stats — merged mining statistics
    nlohmann::json rest_current_merged_payouts();    // /current_merged_payouts — merged payouts
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

    // Track a found block for the /recent_blocks endpoint
    void record_found_block(uint64_t height, const uint256& hash, uint64_t ts = 0,
                            const std::string& chain = "LTC");
    
    // Stratum-style methods (for advanced miners)
    // Job snapshot: holds all template data frozen at the time a mining job was sent.
    // Passed to mining_submit / build_block_from_stratum so the submitted block
    // matches the exact template the miner hashed (not the live/refreshed one).
    struct JobSnapshot {
        std::string coinb1, coinb2;
        std::string gbt_prevhash;      // BE display hex
        std::string nbits;             // BE hex e.g. "1e0fffff"
        uint32_t    version{0};
        std::vector<std::string> merkle_branches;
        std::vector<std::string> tx_data;   // raw tx hex from GBT
        std::string mweb;
        bool        segwit_active{false};
        uint256     prev_share_hash;  // share chain tip when this job was built
        uint64_t    subsidy{0};       // coinbasevalue frozen at job creation
        std::string witness_commitment_hex;  // P2Pool witness commitment frozen at job creation
        uint256     witness_root;            // raw wtxid merkle root frozen at job creation
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
    void set_best_share_hash_fn(std::function<uint256()> fn) { m_best_share_hash_fn = std::move(fn); }
    std::function<uint256()> get_best_share_hash_fn() const { return m_best_share_hash_fn; }

    // Hook: computes PPLNS expected payouts from the share tracker
    using pplns_fn_t = std::function<std::map<std::vector<unsigned char>, double>(
        const uint256& best_hash, const uint256& block_target,
        uint64_t subsidy, const std::vector<unsigned char>& donation_script)>;
    void set_pplns_fn(pplns_fn_t fn) { m_pplns_fn = std::move(fn); }

    // Hook: computes the p2pool ref_hash for a given coinbase scriptSig.
    // Returns (ref_hash, last_txout_nonce) pair.  The ref_hash depends on
    // the share tracker state (prev_share, absheight, abswork, etc.) and
    // the miner's payout address (implicit via existing connection state).
    // Called per-connection during work generation.
    using ref_hash_fn_t = std::function<std::pair<uint256, uint64_t>(
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
        std::vector<unsigned char> payout_script;
        std::map<uint32_t, std::vector<unsigned char>> merged_addresses;
        uint32_t block_version{0};
        uint256  prev_block_hash;
        uint32_t timestamp{0};
        uint32_t bits{0};
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
    };
    using create_share_fn_t = std::function<void(const ShareCreationParams& params)>;
    void set_create_share_fn(create_share_fn_t fn) { m_create_share_fn = std::move(fn); }

    // Operator-controlled V36 message blob to embed into locally created shares.
    // Empty means no message_data in locally produced shares.
    void set_operator_message_blob(const std::vector<unsigned char>& blob);
    std::vector<unsigned char> get_operator_message_blob() const;

    // Hook: expose decoded protocol messages (e.g. from current best share)
    // through API methods for dashboard/monitoring clients.
    using protocol_messages_fn_t = std::function<nlohmann::json()>;
    void set_protocol_messages_fn(protocol_messages_fn_t fn) { m_protocol_messages_fn = std::move(fn); }

    // Integrated merged mining manager
    void set_merged_mining_manager(c2pool::merged::MergedMiningManager* mgr) { m_mm_manager = mgr; }

    // Sharechain stats callback — returns live tracker data for the /sharechain/stats endpoint
    using sharechain_stats_fn_t = std::function<nlohmann::json()>;
    void set_sharechain_stats_fn(sharechain_stats_fn_t fn) { m_sharechain_stats_fn = std::move(fn); }

    // Sharechain window callback — returns per-share data for the defragmenter grid
    using sharechain_window_fn_t = std::function<nlohmann::json()>;
    void set_sharechain_window_fn(sharechain_window_fn_t fn) { m_sharechain_window_fn = std::move(fn); }

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

    // Block acceptance verification: schedule async checks at +10s, +30s, +120s.
    // The verify callback returns: >0=confirmed, <0=orphaned, 0=pending.
    using block_verify_fn_t = std::function<int(const std::string& hash)>;
    void set_block_verify_fn(block_verify_fn_t fn);
    void set_io_context(boost::asio::io_context* ctx) { m_context = ctx; }
    void schedule_block_verification(const std::string& block_hash);

    // Callback fired whenever a block submission is attempted.
    // Arguments: header hex (first 80 bytes), stale_info (none=accepted, orphan=stale prev, doa=daemon rejected).
    void set_on_block_submitted(std::function<void(const std::string& header_hex, int stale_info)> fn);

    // Callback for P2P block relay — receives full block hex for direct daemon P2P broadcast.
    void set_on_block_relay(std::function<void(const std::string& full_block_hex)> fn);
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
    static std::pair<std::string, std::string> build_coinbase_parts(
        const nlohmann::json& tmpl, uint64_t coinbase_value,
        const std::vector<std::pair<std::string,uint64_t>>& outputs,
        bool raw_scripts = false,
        const std::vector<uint8_t>& mm_commitment = {},
        const std::string& witness_commitment_hex = {},
        const std::string& ref_hash_hex = {});
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
    std::atomic<bool>       m_work_valid{false};
    nlohmann::json          m_cached_template;
    std::vector<std::string> m_cached_merkle_branches;   // Stratum merkle branches
    std::string             m_cached_coinb1;
    std::string             m_cached_coinb2;
    mutable std::mutex      m_work_mutex;

    // Block-found callback (header_hex, stale_info: 0=none, 253=orphan, 254=doa)
    std::function<void(const std::string&, int)> m_on_block_submitted;

    // P2P block relay callback — receives the full block hex for direct P2P broadcast.
    // Only called for accepted blocks (not stale/orphan/doa).
    std::function<void(const std::string&)> m_on_block_relay;

    // Share tracker hook
    std::function<uint256()> m_best_share_hash_fn;

    // Sharechain stats callback
    sharechain_stats_fn_t m_sharechain_stats_fn;
    sharechain_window_fn_t m_sharechain_window_fn;

    // PPLNS computation hook
    pplns_fn_t m_pplns_fn;

    // Ref hash computation hook (per-connection work generation)
    ref_hash_fn_t m_ref_hash_fn;

    // Cached PPLNS outputs for per-connection coinbase generation
    // (populated in refresh_work, consumed in build_connection_coinbase)
    std::vector<std::pair<std::string, uint64_t>> m_cached_pplns_outputs;
    bool m_cached_raw_scripts{false};
    std::string m_cached_witness_commitment;
    uint256 m_cached_witness_root;  // raw wtxid merkle root
    std::vector<uint8_t> m_cached_mm_commitment;
    std::string m_cached_mweb;  // MWEB extension data from GBT (Litecoin)

    // Share creation hook
    create_share_fn_t m_create_share_fn;

    // Protocol message extraction hook for API display.
    protocol_messages_fn_t m_protocol_messages_fn;

    // Operator blob injected into locally created shares (thread-safe).
    mutable std::mutex m_message_blob_mutex;
    std::vector<unsigned char> m_operator_message_blob;

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

    // Cached network difficulty (computed from bits in refresh_work)
    std::atomic<double> m_network_difficulty{0.0};

    // Recently found blocks for /recent_blocks
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
    };
    std::vector<FoundBlock> m_found_blocks;   // newest first, capped at 100
    mutable std::mutex      m_blocks_mutex;

    block_verify_fn_t m_block_verify_fn;
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

    // Primary payout address (for legacy /payout_addr endpoint)
    void set_payout_address(const std::string& addr) { m_payout_address = addr; }
    const std::string& get_payout_address() const { return m_payout_address; }

    // P2P peer info callback — returns JSON array of peer objects [{address,version,incoming,uptime,txpool_size}]
    using peer_info_fn_t = std::function<nlohmann::json()>;
    void set_peer_info_fn(peer_info_fn_t fn) { m_peer_info_fn = std::move(fn); }

    // Port configuration for /node_info
    void set_p2p_port(uint16_t port) { m_p2p_port = port; }
    void set_worker_port(uint16_t port) { m_worker_port = port; }

    // Best share difficulty tracking (for /best_share, /miner_stats)
    void record_share_difficulty(double difficulty, const std::string& miner);

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
    // Primary payout address for legacy API
    std::string m_payout_address;

    // P2P peer info callback
    peer_info_fn_t m_peer_info_fn;

    // Port configuration
    uint16_t m_p2p_port{9338};
    uint16_t m_worker_port{9327};

    // Best share difficulty tracking
    struct BestDifficulty {
        double all_time{0.0};
        double session{0.0};
        double round{0.0};
        std::string miner;
        uint64_t timestamp{0};
        uint64_t round_start{0};
    };
    BestDifficulty m_best_difficulty;
    mutable std::mutex m_best_diff_mutex;

    // Stat log for /web/log JSON endpoint (rolling 24h window)
    struct StatLogEntry {
        double time;
        double pool_hash_rate;
        double pool_stale_prop;
        nlohmann::json local_hash_rates;
        uint64_t shares;
        uint64_t stale_shares;
        double current_payout;
        nlohmann::json peers;         // {incoming, outgoing}
        double attempts_to_share;
        double attempts_to_block;
        double block_value;
    };
    std::vector<StatLogEntry> m_stat_log;
    mutable std::mutex m_stat_log_mutex;

    // Network difficulty history for /network_difficulty
    struct NetDiffSample { double ts; double difficulty; std::string source; };
    std::vector<NetDiffSample> m_netdiff_history;  // newest-first, capped at 10000
    mutable std::mutex m_netdiff_mutex;

    // ── Stratum worker session tracking ──────────────────────────────────
public:
    struct WorkerInfo {
        std::string username;      // miner address (after parsing)
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
    net::io_context& ioc_;
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

    // Stratum server control methods
    bool start_stratum_server();
    void stop_stratum_server();
    bool is_stratum_running() const;
    void set_stratum_port(uint16_t port);
    uint16_t get_stratum_port() const;

    // Dashboard directory for static file serving
    void set_dashboard_dir(const std::string& dir);

    // Wire a live coin-daemon RPC connection for block template generation
    void set_coin_rpc(ltc::coin::NodeRPC* rpc, ltc::interfaces::Node* coin = nullptr);
    // Wire an embedded coin node (Phase 4 — preferred over RPC when set)
    void set_embedded_node(ltc::coin::CoinNodeInterface* node);
    // Forward block-found callback to the underlying MiningInterface
    void set_on_block_submitted(std::function<void(const std::string&, int)> fn);
    // Forward P2P block relay callback to the underlying MiningInterface
    void set_on_block_relay(std::function<void(const std::string&)> fn);
    // Immediately refresh the cached block template (call when a new block arrives)
    void trigger_work_refresh();
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

/// Stratum Session handler for native Stratum protocol (TCP + line-delimited JSON)
class StratumSession : public std::enable_shared_from_this<StratumSession>
{
    tcp::socket socket_;
    boost::asio::streambuf buffer_;
    std::shared_ptr<MiningInterface> mining_interface_;
    std::string subscription_id_;
    std::string extranonce1_;
    std::string username_;
    bool subscribed_ = false;
    bool authorized_ = false;
    bool need_initial_setup_ = false;
    static std::atomic<uint64_t> job_counter_;
    
    // Per-connection VARDIFF via HashrateTracker
    c2pool::hashrate::HashrateTracker hashrate_tracker_;
    
    // Active jobs for stale detection (job_id → prevhash at time of issue)
    struct JobEntry {
        std::string prevhash;      // Stratum-format (swapped) for stale detection
        std::string gbt_prevhash;  // Raw GBT previousblockhash (BE display hex) for header reconstruction
        std::string nbits;
        uint32_t    ntime{};
        std::string coinb1;
        std::string coinb2;
        uint32_t    version{};
        std::vector<std::string> merkle_branches;
        std::vector<std::string> tx_data;     // raw tx hex from GBT template
        std::string mweb;                      // MWEB extension data
        bool        segwit_active{false};
        uint256     prev_share_hash;  // share chain tip when this job was built
        uint64_t    subsidy{0};       // coinbasevalue frozen at job creation
        std::string witness_commitment_hex;  // P2Pool witness commitment frozen at job creation
        uint256     witness_root;            // raw wtxid merkle root frozen at job creation
    };
    std::unordered_map<std::string, JobEntry> active_jobs_;
    std::string last_prevhash_;  // track prevhash for clean_jobs detection
    static constexpr size_t MAX_ACTIVE_JOBS = 32; // keep last N jobs for late shares + block target checking
    
    // Per-worker statistics
    uint64_t accepted_shares_ = 0;
    uint64_t rejected_shares_ = 0;
    uint64_t stale_shares_    = 0;
    std::chrono::steady_clock::time_point connected_at_;
    std::string session_id_;  // unique key for worker tracking

    // Merged mining: per-chain payout addresses set by the miner.
    // Maps chain_id → address string (e.g. 98 → "DQkw...").
    // Populated via mining.set_merged_addresses or from username format.
    std::map<uint32_t, std::string> merged_addresses_;

    // Periodic work-push timer (fires every SHARE_PERIOD to keep miners on fresh work)
    std::shared_ptr<boost::asio::steady_timer> work_push_timer_;

public:
    explicit StratumSession(tcp::socket socket, std::shared_ptr<MiningInterface> mining_interface);
    void start();

    // Merged mining: return the per-chain payout addresses for share construction.
    const std::map<uint32_t, std::string>& get_merged_addresses() const { return merged_addresses_; }

private:
    std::string generate_subscription_id();
    void read_message();
    void process_message(std::size_t bytes_read);
    
    nlohmann::json handle_subscribe(const nlohmann::json& params, const nlohmann::json& request_id);
    nlohmann::json handle_authorize(const nlohmann::json& params, const nlohmann::json& request_id);
    nlohmann::json handle_submit(const nlohmann::json& params, const nlohmann::json& request_id);
    nlohmann::json handle_set_merged_addresses(const nlohmann::json& params, const nlohmann::json& request_id);
    
    void send_response(const nlohmann::json& response);
    void send_error(int code, const std::string& message, const nlohmann::json& request_id);
    void send_set_difficulty(double difficulty);
    void send_notify_work(bool force_clean = false);
    void start_periodic_work_push();
    
    std::string generate_extranonce1();
    

};

/// Stratum Server for native mining protocol (separate from HTTP)
class StratumServer
{
    net::io_context& ioc_;
    tcp::acceptor acceptor_;
    std::shared_ptr<MiningInterface> mining_interface_;
    std::string bind_address_;
    uint16_t port_;
    bool running_;

public:
    StratumServer(net::io_context& ioc, const std::string& address, uint16_t port, std::shared_ptr<MiningInterface> mining_interface);
    ~StratumServer();

    bool start();
    void stop();
    
    std::string get_bind_address() const { return bind_address_; }
    uint16_t get_port() const { return port_; }
    bool is_running() const { return running_; }

private:
    void accept_connections();
    void handle_accept(boost::system::error_code ec, tcp::socket socket);
};

} // namespace core
