// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once
#include "merged_chain_addr.hpp"
#include "stratum_http.hpp"
#include "stratum_refusal_log.hpp"

#include <memory>
#include <string>
#include <atomic>
#include <mutex>
#include <map>
#include <optional>
#include <unordered_map>
#include <unordered_set>
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
#include <core/stratum_work_source.hpp>
#include <c2pool/hashrate/tracker.hpp>

namespace core {

namespace net = boost::asio;
using tcp = net::ip::tcp;

// IWorkSource is the abstract interface stratum_server holds (defined in
// core/stratum_work_source.hpp). LTC's MiningInterface and BTC's
// btc::stratum::BTCWorkSource both implement it.
using IWorkSource = core::stratum::IWorkSource;

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
        // 8 bytes is the widest prefix a 64-bit size_t can hold, and 8 <= a.size()
        // (std::array<uint8_t, 20>), so no second bounds clause is needed.
        for (int i = 0; i < 8; ++i)
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
public:
    /// Longest inbound Stratum line, excluding the '\n' delimiter. Same bound
    /// as p2pool: its stratum peer is twisted's LineOnlyReceiver
    /// (p2pool util/jsonrpc.py LineBasedPeer, MAX_LENGTH not overridden), and
    /// twisted drops the connection once a line exceeds MAX_LENGTH = 16384.
    /// The read buffer holds kMaxStratumLineBytes + 1 bytes so a line of
    /// exactly kMaxStratumLineBytes plus its '\n' is still accepted.
    static constexpr std::size_t kMaxStratumLineBytes = 16384;

private:
    tcp::socket socket_;
    // Bounded line buffer: a peer whose line runs past kMaxStratumLineBytes
    // without a '\n' is dropped (see read_message()).
    boost::asio::streambuf buffer_{kMaxStratumLineBytes + 1};
    std::deque<std::string> write_queue_;  // async write queue (non-blocking)
    bool writing_ = false;                 // true while an async_write is in flight
    std::shared_ptr<IWorkSource> mining_interface_;
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
        // Heavyweight per-generation template data, refcounted and SHARED
        // across all jobs a session issues for one work generation (interim
        // hardening fix #2 — de-dup of the per-job memory bomb). coinb2 carries
        // the PPLNS payout outputs, the dominant per-job allocation. Contents
        // are immutable after construction; a new payload is only allocated
        // when any byte differs from the previous job's payload (byte-identical
        // reuse ⇒ provably no wire change).
        struct SharedJobPayload {
            std::string coinb1;
            std::string coinb2;                          // includes PPLNS outputs
            std::vector<std::string> merkle_branches;
            std::vector<uint256> frozen_merkle_branches; // segwit txid_merkle_link at template time
            std::vector<unsigned char> frozen_merged_coinbase_info;  // pre-serialized
        };
        std::string prevhash;      // Stratum-format (swapped) for stale detection
        std::string gbt_prevhash;  // Raw GBT previousblockhash (BE display hex) for header reconstruction
        std::string nbits;         // share target bits (used in header the miner hashes)
        uint32_t    ntime{};
        std::shared_ptr<const SharedJobPayload> payload;  // coinb1/coinb2/branches (shared per work generation)
        uint32_t    version{};
        std::shared_ptr<const std::vector<std::string>> tx_data;     // raw tx hex from GBT template (a1: shared/lazy)
        std::string mweb;                      // MWEB extension data
        bool        mweb_active{false};        // template rules named MWEB
        bool        degraded{false};           // template ingress refused (served degraded)
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
        uint256  frozen_witness_root;                  // wtxid_merkle_root at template time
        // The ref the job's coinbase committed to (its OP_RETURN) and that
        // coinbase's last_txout_nonce, for work sources that check or rebuild
        // the share at submit (DGB). Carried as built; no lane rewrites them.
        uint256  frozen_ref_hash;
        uint64_t frozen_last_txout_nonce{0};
        bool     has_frozen{false};
        int64_t  share_version{36};    // AutoRatchet-determined share version at template time
        uint64_t desired_version{36};  // Version vote
        int      stale_info{0};  // 0=none, 253=orphan (block template changed), 254=doa
        // Creation stamp for TTL eviction (steady clock — immune to wall-clock
        // jumps; the wire ntime field above is unchanged and stays wall-clock).
        std::chrono::steady_clock::time_point created_at{};
        // VARDIFF difficulty advertised WITH this job, frozen at creation. The
        // submit gate validates a share against THIS (the target the miner
        // actually received), not the live vardiff, so a vardiff up-retarget
        // between job-issue and submit does not reject in-flight shares. Port
        // of p2pool-dash work.py:477 grace (p2pool judges each share by its own
        // job's target). 0.0 = unset ⇒ gate falls back to the live vardiff.
        double issued_difficulty{0.0};
        // The payout and merged scripts this job's ref_hash committed to: the
        // share made from it carries these, whatever the session's login is
        // by the time the miner submits.
        bool has_payout{false};
        std::vector<unsigned char> payout_script;
        std::map<uint32_t, std::vector<unsigned char>> merged_scripts;
        // The (extranonce2, ntime, nonce, version) submissions seen on this
        // job (StratumConfig::reject_duplicate_submits); shared so the per-
        // submit job copy stays cheap. Lives as long as the job.
        std::shared_ptr<std::unordered_set<std::string>> submitted;
    };
    std::unordered_map<std::string, JobEntry> active_jobs_;
    // Insertion-order companion to active_jobs_ (interim hardening fix #1).
    // unordered_map::begin() is ARBITRARY, so the old
    // `erase(active_jobs_.begin())` capacity eviction could drop the job the
    // miner is CURRENTLY hashing — the nondeterministic stale-reject bug.
    // This deque records job issue order so eviction is genuinely oldest-first
    // (FIFO), and a 300 s TTL sweep on insert mirrors p2pool's ExpiringDict.
    // The most recently issued job (back of the deque) is never evicted.
    std::deque<std::string> job_order_;
    // Ids of jobs this session issued and has since evicted (newest at the
    // back, at most RECENT_EXPIRED_JOBS). A submit whose job id is neither
    // active nor listed here was never issued on this connection, e.g. a
    // result the rig buffered before a node restart: it is still answered
    // "Stale share" but counted as an unknown job, not as genuine stale.
    std::deque<std::string> expired_job_ids_;
    static constexpr size_t RECENT_EXPIRED_JOBS = 256;
    // Per-generation payload cache: reuse the previous job's SharedJobPayload
    // when the freshly built bytes are identical (same work generation, same
    // coinbase, same branches). Byte-compare gate ⇒ wire-identical by design.
    std::shared_ptr<const JobEntry::SharedJobPayload> payload_cache_;
    uint64_t payload_cache_generation_ = 0;
    std::string last_prevhash_;  // track prevhash for clean_jobs detection
    uint64_t last_pushed_generation_ = 0;  // work generation at last push (for safety timer)
    static constexpr size_t MAX_ACTIVE_JOBS = 256; // p2pool keeps all jobs from current block
    static constexpr std::chrono::seconds JOB_TTL{300}; // p2pool ExpiringDict expiry for jobs

    // Per-worker statistics
    uint64_t accepted_shares_ = 0;
    uint64_t rejected_shares_ = 0;
    uint64_t stale_shares_    = 0;  // job id not active: genuine stale + unknown job
    uint64_t doa_shares_      = 0;  // block-template changed at submit (live-vs-frozen prevhash mismatch); accounting only, share still broadcasts
    // Rolling accepted / stale / unknown-job outcomes for the miner page;
    // shared with the worker registry through WorkerInfo::submit_window.
    // Unknown-job submits (job id never issued on this connection) are a
    // subset of stale_shares_.
    std::shared_ptr<core::stratum::SubmitOutcomeWindow> submit_window_ =
        std::make_shared<core::stratum::SubmitOutcomeWindow>();
    std::chrono::steady_clock::time_point connected_at_;
    // Last inbound-line timestamp (zombie-session reaper, StratumConfig::
    // session_idle_timeout_sec). Updated on every received stratum line; a
    // half-open NAT-dead peer never advances it. Init to connected_at_.
    std::chrono::steady_clock::time_point last_activity_;
    // Last OUTBOUND mining.notify timestamp (idle keepalive-notify, StratumConfig::
    // keepalive_notify_sec). Distinct from last_activity_ (inbound): the keepalive
    // must fire on an idle-but-live session that is receiving nothing AND sending
    // nothing. Updated whenever send_notify_work() actually emits a notify; init
    // to connected_at_.
    std::chrono::steady_clock::time_point last_notify_at_;
    std::string session_id_;
    // The first inbound line has been read: only that one is checked for an
    // HTTP request line (try_http_handoff). Empty lines before it are skipped
    // while HTTP is on (RFC 9112 2.2), at most 4.
    bool first_line_seen_ = false;
    int blank_lines_skipped_ = 0;
    // Remote address, read once at construction (the socket is connected
    // then; remote_endpoint() fails after close). Keys the per-IP cap.
    boost::asio::ip::address peer_address_;

    // Reject-reason diagnostics throttle: emit the low-diff (P5) and
    // malformed-params (P1) reject lines at most once per REJECT_LOG_INTERVAL
    // per session so a rig hammering rejects cannot flood the log. INFO level.
    std::chrono::steady_clock::time_point last_lowdiff_log_{};
    std::chrono::steady_clock::time_point last_badparams_log_{};
    static constexpr std::chrono::seconds REJECT_LOG_INTERVAL{5};

    // Merged mining: per-chain payout addresses set by the miner.
    std::map<uint32_t, std::string> merged_addresses_;
    // The ones sent with mining.set_merged_addresses: the only entries that
    // outlive a re-authorize (the login's own are resolved again from it).
    std::map<uint32_t, std::string> set_merged_addresses_;
    // The last successful login's primary and the merged addresses it gave
    // itself (not set_merged_addresses, not auto-derived): kept by a
    // re-authorize with the same primary.
    std::string login_primary_;
    std::map<uint32_t, std::string> login_given_;
    // The login has no payout address a share can carry (empty, invalid,
    // another coin's) and the work source redistributes it: the jobs carry
    // parent_script_ (p2pool's case 4) or an empty payout.
    bool payout_unusable_{false};
    std::vector<unsigned char> parent_script_;
    std::string payout_warning_;   // shown with the worker ("address invalid → redistributed")
    // The scriptPubKey a merged entry pays on its chain
    // (core::merged_addr::merged_payout_script).
    std::vector<unsigned char> merged_script_for(uint32_t chain_id, const std::string& addr) const;
    bool testnet_network() const;
    // The merged-chain identification table (built once per session).
    const std::vector<core::merged_addr::ChainAddrInfo>& merged_table() const;
    mutable std::vector<core::merged_addr::ChainAddrInfo> merged_table_;
    mutable bool merged_table_built_{false};

    // BIP 310 version-rolling (ASICBoost) state
    static constexpr uint32_t POOL_VERSION_MASK = 0x1fffe000;
    bool version_rolling_enabled_ = false;
    uint32_t version_rolling_mask_ = 0;

    // Extranonce subscription (NiceHash + BIP 310 subscribe-extranonce)
    bool extranonce_subscribe_ = false;

    // Suggested difficulty from miner (mining.suggest_difficulty)
    double suggested_difficulty_ = 0.0;

    // Per-miner SHARE difficulty from a colon-less "ADDR/<diff>" login token
    // (p2pool desired_share_target). Unset when absent or not a finite
    // value > 0. Parsed here only; consumers wire it per coin.
    std::optional<double> share_difficulty_override_;

    // Difficulty last sent with mining.set_difficulty (internal units; 0 =
    // none yet). send_notify_work() sends set_difficulty ahead of any job
    // whose issued difficulty differs from it, so the miner hashes every job
    // at the difficulty the job is judged and credited at.
    double advertised_difficulty_ = 0.0;
    // "d=N" in the mining.authorize password: the session's start difficulty,
    // taken from the first successful authorize only; a bad value is logged
    // once per session.
    bool password_diff_applied_ = false;
    bool password_diff_logged_ = false;

    // Periodic work-push timer — member (not shared_ptr) so RAII guarantees
    // the timer outlives all its callbacks.  Matches p2pool Twisted semantics
    // where the transport/protocol object owns its timers.
    boost::asio::steady_timer work_push_timer_;
    // One-shot guard so the periodic work-push / idle-keepalive timer is armed
    // exactly once. It is armed at subscribe (so a subscribe-only backup session
    // is kept alive by the keepalive) and again after authorize (payout-aware
    // resend); this flag makes the second call a no-op so the timer chain never
    // forks into a double-notify cadence.
    bool periodic_push_started_ = false;

    // Handshake deadline (zombie-session fix, StratumConfig::handshake_timeout_
    // sec): armed at start(), disarmed once authorize completes. A session that
    // never authorizes (half-open / probe) is dropped when it fires.
    boost::asio::steady_timer handshake_timer_;

    // A held job (CoinbaseResult::held): one pending retry per session, for
    // at most StratumConfig::job_hold_limit_sec since the hold began; past it
    // the session stops retrying (the miner keeps its last valid job) until
    // the next notify. hold_retry_clean_: a notify held meanwhile asked for
    // clean jobs, so the next job sent does (the retry's, or one built first
    // by another notify), also after the limit ended the retries.
    bool hold_retry_pending_ = false;
    bool hold_retry_clean_ = false;
    std::chrono::steady_clock::time_point hold_since_{};
    uint64_t hold_retries_ = 0;

    // Work not ready (no template, a template without difficulty bits, or a
    // job suppressed for want of an atomic snapshot / a real prevhash): one
    // pending 1 s retry per session, however many notifies arrive meanwhile
    // (template_retry_pending_ is set while its timer is armed and cleared
    // only by its handler). template_waiting_: a wait is active (set by each
    // not-ready exit, cleared once the work is ready); a retry that finds the
    // wait over and nothing owed sends nothing. template_retry_clean_: a
    // clean request is owed (made during the wait, or carried by a call that
    // ended without a job), so the next job sent carries clean_jobs=true —
    // the retry's, or one sent first by any other notify.
    bool template_retry_pending_ = false;
    bool template_waiting_ = false;
    bool template_retry_clean_ = false;

public:
    explicit StratumSession(tcp::socket socket, std::shared_ptr<IWorkSource> mining_interface,
                            StratumServer* server = nullptr);
    void start();

    bool is_connected() const { return socket_.is_open(); }
    bool is_subscribed() const { return subscribed_; }
    bool is_authorized() const { return authorized_; }
    // Seconds since the last inbound stratum line (zombie-session reaper).
    double seconds_since_activity() const {
        return std::chrono::duration<double>(
                   std::chrono::steady_clock::now() - last_activity_).count();
    }
    // Seconds since the last OUTBOUND mining.notify (idle keepalive-notify).
    double seconds_since_last_notify() const {
        return std::chrono::duration<double>(
                   std::chrono::steady_clock::now() - last_notify_at_).count();
    }
    // Seconds since the TCP connection was accepted (handshake deadline).
    double seconds_since_connect() const {
        return std::chrono::duration<double>(
                   std::chrono::steady_clock::now() - connected_at_).count();
    }
    const boost::asio::ip::address& peer_address() const { return peer_address_; }
    // The idle reaper's rule (StratumConfig::session_idle_timeout_sec): no
    // INBOUND line for more than timeout s (notifies sent to the miner do not
    // count). With OS TCP keepalive on, an authorized session is never idle-
    // reaped: keepalive is the liveness authority, and a rig on a high fixed
    // difficulty can legitimately stay quiet past the window. 0 = off.
    bool idle_reapable(uint32_t timeout, bool keepalive_on) const;
    // Why this session may be closed now under cfg's hygiene knobs: past the
    // handshake deadline without an authorize, or idle_reapable. nullptr =
    // keep it. The miner cap uses it to free a slot at the moment a new
    // connection would be refused (between reaper sweeps and timer firings).
    const char* reclaim_reason(const core::stratum::StratumConfig& cfg) const;
    // Reap a stale/zombie session: cancel timers + close the socket. The pending
    // async_read then fails and runs the normal disconnect path. Idempotent.
    void drop_stale(const char* reason);
    // Diagnostics / test introspection (read-only; call quiesced or from the
    // session's io_context thread — active_jobs_ mutates on notify/submit).
    size_t active_job_count() const { return active_jobs_.size(); }
    size_t distinct_job_payloads() const;  // distinct SharedJobPayload blocks retained
    double get_hashrate() const { return hashrate_tracker_.get_current_hashrate(); }
    const std::array<uint8_t, 20>& get_pubkey_hash() const { return pubkey_hash_; }
    const std::map<uint32_t, std::string>& get_merged_addresses() const { return merged_addresses_; }
    const std::optional<double>& get_share_difficulty_override() const { return share_difficulty_override_; }

private:
    std::string generate_subscription_id();
    void read_message();
    void process_message(std::size_t bytes_read);
    // HTTP on the stratum port (core/stratum_http.hpp): when the first line
    // (bytes_read bytes at the front of buffer_) is an HTTP request line and
    // the server has it on, leave the miner sessions, take an HTTP slot under
    // the caps, and hand the socket plus everything buffered to the server's
    // HTTP handler within the hand-off budget; answer 503 over the budget or
    // the per-address share (busy), or when there is no handler or it
    // declines (not served). true: the connection is no longer this
    // session's -- stop reading.
    bool try_http_handoff(std::size_t bytes_read);
    // The first line so far is an empty line (CRLF / LF) and HTTP is on:
    // consume it and keep looking for the request line. true: skipped.
    bool skip_leading_blank_line(std::size_t bytes_read);
    // The stratum side's 503 for an HTTP connection (`kind` picks the body),
    // written on req->socket's io_context, then the close; the write is
    // closed at min(req->deadline, write start +
    // kStratumHttpUnavailableWriteTimeout). `req` (and its slot) is released
    // when both the write and its deadline have completed.
    static void answer_http_unavailable(std::shared_ptr<StratumHttpRequest> req,
                                        const std::string& method, const std::string& target,
                                        StratumHttpUnavailable kind);
    // Test access (core_test).
    friend struct StratumSessionTestAccess;


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

    // Graceful shutdown: cancel timers + close socket. The pending async_read
    // fails with operation_aborted, the read handler runs the standard
    // disconnect path (cancel_timers, unregister_stratum_worker, log). Idempotent.
    // Called by StratumServer::stop() during process shutdown so no queued
    // async handlers reference half-destroyed state when the io_context dies.
    void shutdown() { cancel_timers(); }
private:
    // The work is not ready: remember a clean request and arm the session's
    // single 1 s retry unless one is already pending.
    void retry_notify_when_work_ready(bool force_clean);
    void start_periodic_work_push();
    void schedule_work_push_timer();
    void cancel_timers();
    // Zombie-session fixes (all no-op unless the DASH-set StratumConfig knobs
    // enable them): apply OS TCP keepalive, arm the authorize deadline.
    void apply_socket_keepalive();
    void arm_handshake_timer();

    std::string generate_extranonce1();
    void parse_address_separators(std::string& username, std::string& merged_addr_raw,
                                  std::set<uint32_t>* slash_chains = nullptr);
};

/// OS TCP liveness for one accepted stratum socket under cfg; a no-op unless
/// cfg.tcp_keepalive_enabled. SO_KEEPALIVE everywhere; on Linux also the probe
/// timing (TCP_KEEPIDLE/INTVL/CNT) and TCP_USER_TIMEOUT
/// (StratumConfig::tcp_user_timeout_sec). Best-effort: an option the OS
/// refuses is logged and skipped.
void apply_stratum_tcp_liveness(tcp::socket& socket, const core::stratum::StratumConfig& cfg);

/// What the per-IP cap (StratumConfig::max_stratum_connections_per_ip) counts
/// by: the IPv4 address (an IPv4-mapped IPv6 address counts as its IPv4
/// address), or the /64 of an IPv6 address -- one host is handed a whole /64
/// and could otherwise rotate through it.
boost::asio::ip::address per_ip_cap_key(const boost::asio::ip::address& a);

/// Stratum Server — accepts TCP connections and spawns StratumSession per miner.
class StratumServer
{
    net::io_context& ioc_;
    tcp::acceptor acceptor_;
    std::shared_ptr<IWorkSource> mining_interface_;
    std::string bind_address_;
    uint16_t port_;
    bool running_;

    // Track active sessions for broadcast (p2pool: new_work_event → _send_work)
    mutable std::mutex sessions_mutex_;
    std::set<std::shared_ptr<StratumSession>> sessions_;

    // STRICT per-node miner cap (interim hardening fix #5): connections refused
    // because sessions_.size() >= StratumConfig::max_stratum_connections.
    std::atomic<uint64_t> refused_connections_{0};
    // Connections refused by StratumConfig::max_stratum_connections_per_ip
    // (one remote address already holds that many live sessions).
    std::atomic<uint64_t> refused_per_ip_{0};

    // Drain-mode admission gate (#866 action 2). Default true = the legacy
    // accept path, unchanged. false refuses every new connection regardless of
    // the cap -- the cap alone cannot express "refuse all" because 0 = unlimited.
    std::atomic<bool> accepting_{true};
    std::atomic<uint64_t> refused_draining_{0};

    // Sessions dropped because an inbound line exceeded
    // StratumSession::kMaxStratumLineBytes without a '\n'.
    std::atomic<uint64_t> oversized_line_drops_{0};

    // HTTP on the stratum port (core/stratum_http.hpp). Off until set_http().
    // http_state_ counts the live HTTP connections (total and per cap key;
    // the connection caps count them) and rate-limits their log lines; it is
    // shared with each connection's slot.
    struct HttpState;
    std::shared_ptr<HttpState> http_state_;
    mutable std::mutex http_mutex_;
    bool http_on_ = false;
    StratumHttpHandler http_handler_;
    StratumHttpLimits http_limits_;
    // HTTP requests answered 503 because the hand-off budget, or the
    // per-address share, was in use.
    std::atomic<uint64_t> refused_http_budget_{0};
    std::atomic<uint64_t> refused_http_share_{0};

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

    // Zombie-session idle reaper (StratumConfig::session_idle_timeout_sec).
    // Periodically closes sessions with no inbound activity past the timeout so
    // a NAT-dead peer that OS keepalive somehow missed is still reclaimed.
    // Disarmed (never scheduled) when the timeout is 0 -> legacy no-op.
    boost::asio::steady_timer idle_reap_timer_;
    void start_idle_reaper();

    // Rate-limited refusal WARN lines (StratumConfig::refusal_log_interval_sec):
    // one limiter per cap; the timer emits a pending summary when its window
    // ends even if no further refusal arrives. io-thread state.
    RefusalLogLimiter cap_refusal_log_;
    RefusalLogLimiter per_ip_refusal_log_;
    RefusalLogLimiter http_budget_refusal_log_;
    RefusalLogLimiter http_share_refusal_log_;
    boost::asio::steady_timer refusal_log_timer_;
    std::optional<RefusalLogLimiter::clock::time_point> refusal_log_timer_due_;   // armed for
    std::atomic<uint64_t> refusal_lines_logged_{0};
    void log_refusal(RefusalLogLimiter& lim, const std::string& peer_ip,
                     const std::string& peer, const std::string& detail,
                     const char* total_name, uint64_t total);
    void flush_refusal_logs();
    void arm_refusal_log_timer();

public:
    StratumServer(net::io_context& ioc, const std::string& address, uint16_t port, std::shared_ptr<IWorkSource> mining_interface);
    ~StratumServer();

    bool start();
    void stop();

    /// Push new work to ALL connected miners immediately (p2pool: new_work_event).
    /// Called when best_share changes or new block template arrives.
    /// force_clean=false (a template rebuilt for new transactions on the
    /// same block) sends clean_jobs only where the block's prevhash changed,
    /// so the ASIC pipelines are not wiped once a second.
    void notify_all(bool force_clean = true);

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

    /// Connections refused by the strict per-node miner cap (fix #5).
    uint64_t get_refused_connections() const { return refused_connections_.load(); }
    /// Connections refused by the per-source-IP cap.
    uint64_t get_refused_per_ip() const { return refused_per_ip_.load(); }
    /// Refusal WARN lines written (full + summary), both caps: rate-limited,
    /// unlike the refusal counters.
    uint64_t get_refusal_lines_logged() const { return refusal_lines_logged_.load(); }
    /// Sessions dropped for an over-length line (no '\n' within the cap).
    uint64_t get_oversized_line_drops() const { return oversized_line_drops_.load(); }
    void record_oversized_line_drop() { oversized_line_drops_.fetch_add(1); }
    /// Live session count (dead sessions pruned lazily — see notify_all()).
    /// Miner sessions only: an HTTP request on the stratum port leaves the
    /// sessions once its first line is read (get_http_connection_count).
    size_t get_session_count() const;

    /// HTTP on the stratum port (core/stratum_http.hpp). on=false (the
    /// default) keeps the legacy behaviour: an HTTP request line is just an
    /// invalid stratum line. on=true with a handler hands HTTP connections to
    /// it, within the hand-off budget of `limits` (stratum_http_budget); over
    /// it, and with no handler (or one that declines), they are answered 503.
    /// Any thread; applies to connections whose first line arrives after.
    void set_http(bool on, StratumHttpHandler handler, StratumHttpLimits limits = {});
    bool http_on() const;
    struct HttpConfig {
        bool on = false;
        StratumHttpHandler handler;
        StratumHttpLimits limits;
    };
    /// The switch, handler and limits as of now (sessions read them on the io
    /// thread).
    HttpConfig http_config() const;
    /// max_stratum_connections as of now (0: no cap).
    std::size_t connection_cap() const;
    /// Live HTTP connections taken from this port (they count toward
    /// max_stratum_connections and the per-IP cap, never as sessions).
    size_t get_http_connection_count() const;
    /// HTTP connections handed over (or answered 503) since start.
    uint64_t get_http_requests() const;
    /// HTTP log lines written (rate-limited: full + summary).
    uint64_t get_http_log_lines() const;
    /// Failed-request warning lines written (rate-limited: full + summary).
    uint64_t get_http_error_log_lines() const;
    /// One HTTP connection's place under the caps; a hand-off slot also holds
    /// one unit of the hand-off budget, in total and for its per_ip_cap_key.
    /// Released when its last owner drops it.
    struct HttpSlot;
    /// A slot for one HTTP connection from `peer` under the caps; released
    /// when the returned pointer's last copy goes.
    std::shared_ptr<void> acquire_http_slot(const boost::asio::ip::address& peer);
    enum class HttpRefusal { None, Budget, Share };
    struct HttpHandoff {
        std::shared_ptr<void> slot;              // null when refused
        HttpRefusal refusal = HttpRefusal::None;
    };
    /// One step under one lock: a hand-off slot for `peer` when fewer than
    /// stratum_http_budget(cap, ...).handoffs hand-offs are in progress and
    /// fewer than .per_key from per_ip_cap_key(peer); else the refusal kind
    /// and no slot. A granted slot counts one request.
    HttpHandoff try_acquire_http_handoff(const boost::asio::ip::address& peer, std::size_t cap,
                                         const StratumHttpLimits& limits);
    /// Count and log (rate-limited) one HTTP request answered 503 for
    /// `refusal`. Call on the io thread.
    void record_http_refusal(HttpRefusal refusal, const std::string& peer_ip, std::size_t cap,
                             const StratumHttpLimits& limits);
    /// HTTP requests answered 503 for the hand-off budget / the per-address
    /// share since start.
    uint64_t get_http_refused_budget() const { return refused_http_budget_.load(); }
    uint64_t get_http_refused_share() const { return refused_http_share_.load(); }
    /// Hand-offs in progress; the most at once since start; keys with one or
    /// more in progress.
    size_t get_http_handoffs() const;
    size_t get_http_handoffs_peak() const;
    size_t get_http_handoff_keys() const;
    /// The per-request log callback for an HTTP connection from `peer_ip`.
    std::function<void(const std::string&, const std::string&, unsigned)>
    http_response_logger(const std::string& peer_ip) const;
    /// The failed-request log callback for an HTTP connection from `peer_ip`.
    std::function<void(const std::string&)> http_error_logger(const std::string& peer_ip) const;

    /// Drain-mode hooks (#866 action 2). Default-inert: while accepting is true
    /// (the default) nothing changes. set_accepting(false) closes each new
    /// connection on accept and bumps get_refused_draining(); live sessions are
    /// left alone. Coin-side drain controllers drive these; core has no policy.
    void set_accepting(bool accepting) { accepting_.store(accepting); }
    bool is_accepting() const { return accepting_.load(); }
    uint64_t get_refused_draining() const { return refused_draining_.load(); }
    /// Close up to n live sessions: unauthorized ones first, then lowest
    /// hashrate first. Each close runs the normal disconnect path. Returns the
    /// number closed. Call on the io thread.
    size_t drop_sessions(size_t n);
    /// Diagnostics: {distinct SharedJobPayload blocks, total active jobs}
    /// summed across all sessions. Bounded-memory evidence: distinct payloads
    /// track retained work GENERATIONS, not sessions × jobs. Test/diag hook —
    /// call quiesced (sessions mutate their job maps on the io thread).
    std::pair<size_t, size_t> get_job_payload_stats() const;

    std::string get_bind_address() const { return bind_address_; }
    uint16_t get_port() const { return port_; }
    bool is_running() const { return running_; }

private:
    void accept_connections();
    void handle_accept(boost::system::error_code ec, tcp::socket socket);
};

} // namespace core