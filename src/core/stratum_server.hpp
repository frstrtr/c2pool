#pragma once

#include <memory>
#include <string>
#include <atomic>
#include <mutex>
#include <map>
#include <unordered_map>
#include <iomanip>
#include <sstream>
#include <ctime>
#include <chrono>
#include <set>
#include <array>

#include <deque>

#include <boost/asio.hpp>
#include <nlohmann/json.hpp>

#include <core/log.hpp>
#include <core/uint256.hpp>
#include <c2pool/hashrate/tracker.hpp>

namespace core {

namespace net = boost::asio;
using tcp = net::ip::tcp;

// Forward declaration — defined in web_server.hpp
class MiningInterface;

/// Sliding-window rate monitor matching p2pool's util.math.RateMonitor.
/// Records timestamped work datums for smooth hashrate estimation.
/// Thread-safe: accessed from multiple StratumSession threads + ref_hash_fn.
class RateMonitor {
public:
    struct Datum {
        double timestamp;                     // epoch seconds
        double work;                          // hashes (difficulty × 2^32)
        std::array<uint8_t, 20> pubkey_hash;
        std::string user;
        bool dead;
    };

    explicit RateMonitor(double max_lookback_time)
        : max_lookback_time_(max_lookback_time) {}

    void add_datum(double work, const std::array<uint8_t, 20>& pubkey_hash,
                   const std::string& user, bool dead);

    /// Returns {datums_in_window, effective_time_span}.
    /// If dt==0, uses max_lookback_time_.
    std::pair<std::vector<Datum>, double> get_datums_in_last(double dt = 0) const;

private:
    void prune_locked();  // must hold mutex_
    double max_lookback_time_;
    double first_timestamp_ = 0.0;
    mutable std::deque<Datum> datums_;
    mutable std::mutex mutex_;
};

/// Hasher for 20-byte pubkey_hash (used in per-address hashrate maps).
struct PubkeyHashHasher {
    size_t operator()(const std::array<uint8_t, 20>& a) const {
        size_t h = 0;
        for (int i = 0; i < 8 && i < 20; ++i)
            h |= size_t(a[i]) << (8 * i);
        return h;
    }
};
/// Per-address hashrate map type (p2pool: get_local_addr_rates return type).
using AddrRateMap = std::unordered_map<std::array<uint8_t, 20>, double, PubkeyHashHasher>;

// Forward declaration
class StratumServer;

/// Stratum mining session — one per TCP connection from a miner.
///
/// Handles the full Stratum lifecycle:
///   mining.subscribe → mining.configure → mining.authorize → mining.submit
///
/// Supports BIP 310 extensions (version-rolling, subscribe-extranonce),
/// NiceHash extranonce protocol, and mining.suggest_difficulty.
class StratumSession : public std::enable_shared_from_this<StratumSession>
{
    tcp::socket socket_;
    boost::asio::streambuf buffer_;
    std::deque<std::string> write_queue_;  // async write queue (non-blocking)
    bool writing_ = false;                 // true while an async_write is in flight
    std::shared_ptr<MiningInterface> mining_interface_;
    StratumServer* server_ = nullptr;  // back-pointer for RateMonitor recording
    std::string subscription_id_;
    std::string extranonce1_;
    std::string username_;
    std::string worker_name_;  // worker suffix from "ADDRESS.worker" (e.g. "alpha")
    bool subscribed_ = false;
    bool authorized_ = false;
    bool need_initial_setup_ = false;
    static std::atomic<uint64_t> job_counter_;

    // Per-connection VARDIFF via HashrateTracker
    c2pool::hashrate::HashrateTracker hashrate_tracker_;

    // Miner's pubkey_hash (20 bytes, extracted from address at authorize time).
    // Used for per-address hashrate aggregation (p2pool: get_local_addr_rates).
    std::array<uint8_t, 20> pubkey_hash_{};

    // Active jobs for stale detection (job_id → prevhash at time of issue)
    struct JobEntry {
        std::string prevhash;      // Stratum-format (swapped) for stale detection
        std::string gbt_prevhash;  // Raw GBT previousblockhash (BE display hex) for header reconstruction
        std::string nbits;         // share target bits (used in header the miner hashes)
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
        std::string gbt_block_nbits; // original GBT block bits (for block target check)
        // Frozen share fields from template time
        uint32_t frozen_absheight{0};
        uint128  frozen_abswork;
        uint256  frozen_far_share_hash;
        uint32_t frozen_max_bits{0};
        uint32_t frozen_bits{0};
        uint32_t frozen_timestamp{0};
        uint256  frozen_merged_payout_hash;
        std::vector<uint256> frozen_merkle_branches;  // segwit txid_merkle_link at template time
        uint256  frozen_witness_root;                  // wtxid_merkle_root at template time
        std::vector<unsigned char> frozen_merged_coinbase_info;  // pre-serialized
        bool     has_frozen{false};
        int64_t  share_version{36};    // AutoRatchet-determined share version at template time
        uint64_t desired_version{36};  // Version vote
        int      stale_info{0};  // 0=none, 253=orphan (block template changed), 254=doa
    };
    std::unordered_map<std::string, JobEntry> active_jobs_;
    std::string last_prevhash_;  // track prevhash for clean_jobs detection
    uint64_t last_pushed_generation_ = 0;  // work generation at last push (for safety timer)
    static constexpr size_t MAX_ACTIVE_JOBS = 256; // p2pool keeps all jobs from current block

    // Per-worker statistics
    uint64_t accepted_shares_ = 0;
    uint64_t rejected_shares_ = 0;
    uint64_t stale_shares_    = 0;
    std::chrono::steady_clock::time_point connected_at_;
    std::string session_id_;

    // Merged mining: per-chain payout addresses set by the miner.
    std::map<uint32_t, std::string> merged_addresses_;

    // BIP 310 version-rolling (ASICBoost) state
    static constexpr uint32_t POOL_VERSION_MASK = 0x1fffe000;
    bool version_rolling_enabled_ = false;
    uint32_t version_rolling_mask_ = 0;

    // Extranonce subscription (NiceHash + BIP 310 subscribe-extranonce)
    bool extranonce_subscribe_ = false;

    // Suggested difficulty from miner (mining.suggest_difficulty)
    double suggested_difficulty_ = 0.0;

    // Periodic work-push timer
    std::shared_ptr<boost::asio::steady_timer> work_push_timer_;

public:
    explicit StratumSession(tcp::socket socket, std::shared_ptr<MiningInterface> mining_interface,
                            StratumServer* server = nullptr);
    void start();

    bool is_connected() const { return socket_.is_open(); }
    bool is_subscribed() const { return subscribed_; }
    double get_hashrate() const { return hashrate_tracker_.get_current_hashrate(); }
    const std::array<uint8_t, 20>& get_pubkey_hash() const { return pubkey_hash_; }
    const std::map<uint32_t, std::string>& get_merged_addresses() const { return merged_addresses_; }

private:
    std::string generate_subscription_id();
    void read_message();
    void process_message(std::size_t bytes_read);

    nlohmann::json handle_subscribe(const nlohmann::json& params, const nlohmann::json& request_id);
    nlohmann::json handle_authorize(const nlohmann::json& params, const nlohmann::json& request_id);
    nlohmann::json handle_submit(const nlohmann::json& params, const nlohmann::json& request_id);
    nlohmann::json handle_set_merged_addresses(const nlohmann::json& params, const nlohmann::json& request_id);
    nlohmann::json handle_configure(const nlohmann::json& params, const nlohmann::json& request_id);
    nlohmann::json handle_extranonce_subscribe(const nlohmann::json& params, const nlohmann::json& request_id);
    nlohmann::json handle_suggest_difficulty(const nlohmann::json& params, const nlohmann::json& request_id);

    void send_response(const nlohmann::json& response);
    void do_write();  // drain the async write queue
    void send_error(int code, const std::string& message, const nlohmann::json& request_id);
    void send_set_difficulty(double difficulty);
    void send_set_extranonce(const std::string& extranonce1, int extranonce2_size);
public:
    // If frozen_best_share is provided (non-null), use it instead of reading
    // best_share_hash_fn() live. This prevents PPLNS recomputation race when
    // best_share changes mid-iteration in notify_all().
    void send_notify_work(bool force_clean = false, const uint256* frozen_best_share = nullptr);
private:
    void start_periodic_work_push();
    void schedule_work_push_timer();
    void cancel_timers();

    std::string generate_extranonce1();
    void parse_address_separators(std::string& username, std::string& merged_addr_raw);
};

/// Stratum Server — accepts TCP connections and spawns StratumSession per miner.
class StratumServer
{
    net::io_context& ioc_;
    tcp::acceptor acceptor_;
    std::shared_ptr<MiningInterface> mining_interface_;
    std::string bind_address_;
    uint16_t port_;
    bool running_;

    // Track active sessions for broadcast (p2pool: new_work_event → _send_work)
    mutable std::mutex sessions_mutex_;
    std::set<std::shared_ptr<StratumSession>> sessions_;

    // p2pool RateMonitor pair (work.py:223-226):
    //   local_rate_monitor: per-user hashrate (for get_local_rates)
    //   local_addr_rate_monitor: per-address hashrate (for get_local_addr_rates)
    // Window = 100 × SHARE_PERIOD (p2pool: 100 × STRATUM_SHARE_RATE)
    static constexpr double RATE_MONITOR_WINDOW = 1000.0;  // seconds
    RateMonitor local_rate_monitor_{RATE_MONITOR_WINDOW};
    RateMonitor local_addr_rate_monitor_{RATE_MONITOR_WINDOW};

    // 2-second cache for get_local_addr_rates (p2pool: work.py:1978-1982)
    mutable AddrRateMap addr_rates_cache_;
    mutable double addr_rates_cache_ts_ = 0.0;
    mutable std::mutex cache_mutex_;

public:
    StratumServer(net::io_context& ioc, const std::string& address, uint16_t port, std::shared_ptr<MiningInterface> mining_interface);
    ~StratumServer();

    bool start();
    void stop();

    /// Push new work to ALL connected miners immediately (p2pool: new_work_event).
    /// Called when best_share changes or new block template arrives.
    void notify_all();

    /// Sum of all connected miners' hashrate (H/s).
    double get_total_hashrate() const;

    /// Per-address hashrate aggregation via RateMonitor.
    /// Matches p2pool: get_local_addr_rates() (work.py:1975-1990).
    /// Returns {pubkey_hash → hashrate (H/s)} for all connected miners.
    AddrRateMap get_local_addr_rates() const;

    /// Per-user hashrate + dead hashrate from RateMonitor.
    /// Matches p2pool: get_local_rates() (work.py:1965-1973).
    std::pair<std::unordered_map<std::string, double>,
              std::unordered_map<std::string, double>> get_local_rates() const;

    /// Rate monitor stats for p2pool-style status display.
    struct RateStats {
        double hashrate = 0;       // H/s
        double effective_dt = 0;   // seconds of data in window
        int total_datums = 0;      // pseudoshares in window
        int dead_datums = 0;       // dead pseudoshares
    };
    RateStats get_rate_stats() const;

    /// Record a pseudoshare in rate monitors.
    /// Called from StratumSession::handle_submit for every accepted pseudoshare.
    /// work = difficulty × 2^32 (hashes), matching p2pool's target_to_average_attempts.
    void record_pseudoshare(double work, const std::array<uint8_t, 20>& pubkey_hash,
                            const std::string& user, bool dead);

    /// Register/unregister sessions for broadcast
    void register_session(std::shared_ptr<StratumSession> s);
    void unregister_session(std::shared_ptr<StratumSession> s);

    std::string get_bind_address() const { return bind_address_; }
    uint16_t get_port() const { return port_; }
    bool is_running() const { return running_; }

private:
    void accept_connections();
    void handle_accept(boost::system::error_code ec, tcp::socket socket);
};

} // namespace core
