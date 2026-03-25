#include "stratum_server.hpp"
#include "web_server.hpp"       // MiningInterface
#include "address_utils.hpp"    // address utilities

#include <core/hash.hpp>
#include <core/target_utils.hpp>
#include <btclibs/util/strencodings.h>
#include <crypto/scrypt.h>

#include <iomanip>
#include <sstream>
#include <ctime>
#include <chrono>
#include <cmath>
#include <cstring>
#include <boost/algorithm/string.hpp>

namespace core {

// ─── RateMonitor implementation (p2pool: util.math.RateMonitor) ───

void RateMonitor::prune_locked() {
    double start_time = std::chrono::duration<double>(
        std::chrono::system_clock::now().time_since_epoch()).count() - max_lookback_time_;
    while (!datums_.empty() && datums_.front().timestamp <= start_time)
        datums_.pop_front();
}

void RateMonitor::add_datum(double work, const std::array<uint8_t, 20>& pubkey_hash,
                            const std::string& user, bool dead) {
    std::lock_guard<std::mutex> lock(mutex_);
    prune_locked();
    double t = std::chrono::duration<double>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    if (first_timestamp_ == 0.0) {
        // p2pool: first datum sets first_timestamp but is NOT added to datums
        first_timestamp_ = t;
    } else {
        datums_.push_back({t, work, pubkey_hash, user, dead});
    }
}

std::pair<std::vector<RateMonitor::Datum>, double>
RateMonitor::get_datums_in_last(double dt) const {
    std::lock_guard<std::mutex> lock(mutex_);
    const_cast<RateMonitor*>(this)->prune_locked();
    if (dt <= 0) dt = max_lookback_time_;
    double now = std::chrono::duration<double>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    double cutoff = now - dt;
    std::vector<Datum> result;
    for (const auto& d : datums_) {
        if (d.timestamp > cutoff)
            result.push_back(d);
    }
    double effective_dt = (first_timestamp_ > 0.0)
        ? std::min(dt, now - first_timestamp_)
        : 0.0;
    return {std::move(result), effective_dt};
}

/// Static member definition
std::atomic<uint64_t> StratumSession::job_counter_{0};

StratumServer::StratumServer(net::io_context& ioc, const std::string& address, uint16_t port, std::shared_ptr<MiningInterface> mining_interface)
    : ioc_(ioc)
    , acceptor_(ioc)
    , mining_interface_(mining_interface)
    , bind_address_(address)
    , port_(port)
    , running_(false)
{
}

StratumServer::~StratumServer()
{
    stop();
}

bool StratumServer::start()
{
    try {
        auto const address = net::ip::make_address(bind_address_);
        tcp::endpoint endpoint{address, port_};
        
        acceptor_.open(endpoint.protocol());
        acceptor_.set_option(net::socket_base::reuse_address(true));
        acceptor_.bind(endpoint);
        acceptor_.listen(net::socket_base::max_listen_connections);
        
        running_ = true;
        accept_connections();
        
        LOG_INFO << "StratumServer started on " << bind_address_ << ":" << port_;
        return true;
        
    } catch (const std::exception& e) {
        LOG_ERROR << "Failed to start StratumServer: " << e.what();
        return false;
    }
}

void StratumServer::stop()
{
    if (running_) {
        try {
            acceptor_.close();
            running_ = false;
            LOG_INFO << "StratumServer stopped";
        } catch (const std::exception& e) {
            LOG_ERROR << "Error stopping StratumServer: " << e.what();
        }
    }
}

void StratumServer::accept_connections()
{
    acceptor_.async_accept(
        [this](boost::system::error_code ec, tcp::socket socket)
        {
            handle_accept(ec, std::move(socket));
        });
}

void StratumServer::handle_accept(boost::system::error_code ec, tcp::socket socket)
{
    if (!ec) {
        // Create, register, and start Stratum session
        auto session = std::make_shared<StratumSession>(std::move(socket), mining_interface_, this);
        register_session(session);
        session->start();
    } else {
        LOG_ERROR << "Stratum accept error: " << ec.message();
    }

    // Continue accepting new connections
    if (running_) {
        accept_connections();
    }
}

void StratumServer::register_session(std::shared_ptr<StratumSession> s)
{
    std::lock_guard<std::mutex> lock(sessions_mutex_);
    sessions_.insert(std::move(s));
}

void StratumServer::unregister_session(std::shared_ptr<StratumSession> s)
{
    std::lock_guard<std::mutex> lock(sessions_mutex_);
    sessions_.erase(s);
}

double StratumServer::get_total_hashrate() const
{
    // Sum all hashrate from the addr rate monitor (consistent with get_local_addr_rates)
    auto [datums, dt] = local_addr_rate_monitor_.get_datums_in_last();
    if (dt <= 0) return 0.0;
    double total_work = 0.0;
    for (const auto& d : datums)
        total_work += d.work;
    return total_work / dt;
}

AddrRateMap StratumServer::get_local_addr_rates() const
{
    // p2pool: get_local_addr_rates() with 2-second cache (work.py:1975-1990).
    // Uses RateMonitor (records ALL pseudoshares at VARDIFF target) instead of
    // summing per-session hashrate (which only counted pool-quality shares).
    double now = std::chrono::duration<double>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    {
        std::lock_guard<std::mutex> lock(cache_mutex_);
        if (now - addr_rates_cache_ts_ < 2.0)
            return addr_rates_cache_;
    }

    auto [datums, dt] = local_addr_rate_monitor_.get_datums_in_last();
    AddrRateMap rates;
    if (dt > 0) {
        for (const auto& d : datums)
            rates[d.pubkey_hash] += d.work / dt;
    }

    {
        std::lock_guard<std::mutex> lock(cache_mutex_);
        addr_rates_cache_ = rates;
        addr_rates_cache_ts_ = now;
    }
    return rates;
}

std::pair<std::unordered_map<std::string, double>,
          std::unordered_map<std::string, double>>
StratumServer::get_local_rates() const
{
    // p2pool: get_local_rates() (work.py:1965-1973)
    auto [datums, dt] = local_rate_monitor_.get_datums_in_last();
    std::unordered_map<std::string, double> hash_rates, dead_hash_rates;
    if (dt > 0) {
        for (const auto& d : datums) {
            hash_rates[d.user] += d.work / dt;
            if (d.dead)
                dead_hash_rates[d.user] += d.work / dt;
        }
    }
    return {hash_rates, dead_hash_rates};
}

void StratumServer::record_pseudoshare(double work, const std::array<uint8_t, 20>& pubkey_hash,
                                        const std::string& user, bool dead)
{
    local_rate_monitor_.add_datum(work, pubkey_hash, user, dead);
    local_addr_rate_monitor_.add_datum(work, pubkey_hash, user, dead);
}

void StratumServer::notify_all()
{
    // ── Lock hierarchy: m_work_mutex (1) > sessions_mutex_ (2) ──
    // send_notify_work() acquires m_work_mutex internally.
    // We must NOT hold sessions_mutex_ while calling it, otherwise:
    //   Thread A: sessions_mutex_ → m_work_mutex  (here)
    //   Thread B: m_work_mutex → sessions_mutex_  (build_connection_coinbase → get_local_addr_rates)
    //   = ABBA deadlock.
    //
    // Pattern: snapshot session shared_ptrs under lock, release, then notify.
    // Sessions are shared_ptr so they stay alive even if unregistered mid-iteration.
    std::vector<std::shared_ptr<StratumSession>> snapshot;
    {
        std::lock_guard<std::mutex> lock(sessions_mutex_);
        snapshot.reserve(sessions_.size());
        for (auto& s : sessions_)
            snapshot.push_back(s);
        // Prune dead sessions while we hold the lock
        for (auto it = sessions_.begin(); it != sessions_.end(); ) {
            if (!(*it)->is_connected())
                it = sessions_.erase(it);
            else
                ++it;
        }
    }
    // sessions_mutex_ RELEASED — safe to call into m_work_mutex territory
    for (auto& s : snapshot) {
        try {
            if (s->is_connected())
                s->send_notify_work(false);
        } catch (...) {}
    }
}

/// StratumSession Implementation
StratumSession::StratumSession(tcp::socket socket, std::shared_ptr<MiningInterface> mining_interface,
                               StratumServer* server)
    : socket_(std::move(socket))
    , mining_interface_(mining_interface)
    , server_(server)
    , connected_at_(std::chrono::steady_clock::now())
{
    subscription_id_ = generate_subscription_id();
    extranonce1_ = generate_extranonce1();
    session_id_ = subscription_id_;  // unique session key

    // Apply stratum tuning from MiningInterface config (populated from CLI/YAML)
    const auto& cfg = mining_interface_->get_stratum_config();
    hashrate_tracker_.set_difficulty_bounds(cfg.min_difficulty, cfg.max_difficulty);
    hashrate_tracker_.set_target_time_per_mining_share(cfg.target_time);
    if (cfg.vardiff_enabled)
        hashrate_tracker_.enable_vardiff();
}

void StratumSession::start()
{
    boost::system::error_code ec;
    auto ep = socket_.remote_endpoint(ec);
    if (ec) return; // socket closed before start() was dispatched
    LOG_INFO << "StratumSession started for client: " << ep;
    read_message();
}

std::string StratumSession::generate_subscription_id()
{
    static std::atomic<uint64_t> subscription_counter{0};
    return "sub_" + std::to_string(subscription_counter.fetch_add(1));
}

void StratumSession::read_message()
{
    auto self = shared_from_this();
    
    boost::asio::async_read_until(socket_, buffer_, '\n',
        [self](boost::system::error_code ec, std::size_t bytes_read)
        {
            if (!ec) {
                self->process_message(bytes_read);
                self->read_message();  // Continue reading
            } else {
                // Session disconnected — unregister from worker tracking
                if (self->authorized_ && self->mining_interface_) {
                    self->mining_interface_->unregister_stratum_worker(self->session_id_);
                }
                LOG_INFO << "StratumSession ended: " << ec.message();
            }
        });
}

void StratumSession::process_message(std::size_t bytes_read)
{
    try {
        std::istream is(&buffer_);
        std::string line;
        std::getline(is, line);
        
        if (!line.empty() && line.back() == '\r') {
            line.pop_back();  // Remove \r if present
        }
        
        LOG_TRACE << "[Stratum] Received: " << line;
        
        auto request = nlohmann::json::parse(line);
        std::string method = request.value("method", "");
        auto params = request.value("params", nlohmann::json::array());
        auto id = request.value("id", nlohmann::json{});
        
        nlohmann::json response;
        
        if (method == "mining.subscribe") {
            response = handle_subscribe(params, id);
        } else if (method == "mining.authorize") {
            response = handle_authorize(params, id);
        } else if (method == "mining.submit") {
            response = handle_submit(params, id);
        } else if (method == "mining.configure") {
            response = handle_configure(params, id);
        } else if (method == "mining.extranonce.subscribe") {
            response = handle_extranonce_subscribe(params, id);
        } else if (method == "mining.suggest_difficulty") {
            response = handle_suggest_difficulty(params, id);
        } else if (method == "mining.set_merged_addresses") {
            response = handle_set_merged_addresses(params, id);
        } else {
            // Unknown method
            send_error(-1, "Unknown method", id);
            return;
        }

        send_response(response);

        // After subscribe response is sent, follow up with difficulty + work.
        // p2pool: pseudoshare difficulty starts low and VARDIFF ramps it up.
        // Do NOT floor at pool share_bits — that defeats VARDIFF.
        if (method == "mining.subscribe") {
            double initial_diff = (suggested_difficulty_ > 0.0)
                ? suggested_difficulty_
                : hashrate_tracker_.get_current_difficulty();
            send_set_difficulty(initial_diff);
            send_notify_work();
        }
        
    } catch (const std::exception& e) {
        LOG_ERROR << "Error processing Stratum message: " << e.what();
        send_error(-2, "Invalid JSON", nlohmann::json{});
    }
}

nlohmann::json StratumSession::handle_subscribe(const nlohmann::json& params, const nlohmann::json& request_id)
{
    subscribed_ = true;
    
    nlohmann::json response;
    response["id"] = request_id;
    response["result"] = nlohmann::json::array({
        nlohmann::json::array({
            nlohmann::json::array({"mining.set_difficulty", subscription_id_}),
            nlohmann::json::array({"mining.notify", subscription_id_})
        }),
        extranonce1_,
        4  // extranonce2_size = 4 bytes
    });
    response["error"] = nullptr;
    
    LOG_INFO << "Mining subscription successful for: " << subscription_id_;
    
    // NOTE: set_difficulty + notify are sent from process_message()
    // AFTER this response is written, so the miner gets the subscribe
    // reply (with extranonce1) before any work notifications.
    
    return response;
}

nlohmann::json StratumSession::handle_authorize(const nlohmann::json& params, const nlohmann::json& request_id)
{
    if (params.size() >= 1 && params[0].is_string()) {
        username_ = params[0];
        authorized_ = true;

        // ─── Step 1: Strip fixed difficulty suffix (+N) before any parsing ───
        // Format: "ADDRESS+1024" or "ADDR,ADDR+512"  →  suggested_difficulty_=N
        {
            auto plus_pos = username_.rfind('+');
            if (plus_pos != std::string::npos && plus_pos + 1 < username_.size()) {
                std::string diff_str = username_.substr(plus_pos + 1);
                try {
                    double fixed_diff = std::stod(diff_str);
                    if (fixed_diff > 0.0) {
                        suggested_difficulty_ = fixed_diff;
                        hashrate_tracker_.set_difficulty_hint(fixed_diff);
                        LOG_INFO << "[Stratum] Fixed difficulty from username: " << fixed_diff;
                    }
                } catch (...) {}
                username_ = username_.substr(0, plus_pos);
            }
        }

        // ─── Step 2: Strip worker name suffix ───
        // Separators: "." and "_" (Python compat)
        // Worker name is always AFTER the last address, so strip from the end.
        auto dot_pos = username_.rfind('.');
        if (dot_pos != std::string::npos && dot_pos > 20)
            username_ = username_.substr(0, dot_pos);
        auto underscore_pos = username_.rfind('_');
        if (underscore_pos != std::string::npos && underscore_pos > 20)
            username_ = username_.substr(0, underscore_pos);

        // ─── Step 3: Parse multi-chain addresses ───
        // Supported separator formats for merged mining addresses:
        //   Slash+colon: PRIMARY/CHAIN_ID:ADDR/CHAIN_ID:ADDR   (explicit chain IDs)
        //   Comma:       PRIMARY,MERGED_ADDR                    (standard Stratum)
        //   Pipe:        PRIMARY|MERGED_ADDR                    (Vnish firmware)
        //   Space:       PRIMARY MERGED_ADDR                    (some web UIs)
        //   Semicolon:   PRIMARY;MERGED_ADDR                    (alternative separator)
        //
        // Vnish firmware and some ASIC control software cannot use commas in the
        // login field, so we support pipe (|) and space as alternatives.
        // ─── Merged chain address identification table ───
        // Each entry: {chain_id, bech32_hrps, base58_version_bytes}
        // Used to auto-detect which chain a merged address belongs to.
        struct ChainAddrInfo {
            uint32_t chain_id;
            std::vector<std::string> hrps;
            std::vector<uint8_t> versions;
        };
        static const std::vector<ChainAddrInfo> MERGED_CHAINS = {
            // DOGE: D... (0x1e), 9/A... (0x16), testnet n... (0x71)
            {98,   {},      {0x1e, 0x16, 0x71}},
            // PEP:  P... (0x38), testnet n... (0x71)
            {63,   {},      {0x38, 0x16, 0x71}},
            // BELLS: B... (0x19), bech32 "bel"/"tbel"
            {16,   {"bel", "tbel"}, {0x19, 0x1e, 0x21}},
            // LKY:  L... (0x2f), testnet n... (0x71)
            {8211, {},      {0x2f, 0x05, 0x71}},
            // JKC:  7... (0x10), testnet m/n... (0x6f)
            {8224, {},      {0x10, 0x05, 0x6f}},
            // SHIC: S... (0x3f), testnet n... (0x71)
            {74,   {},      {0x3f, 0x16, 0x71}},
            // DINGO: same versions as DOGE (fork), chain_id=98 (conflicts with DOGE!)
            // Cannot be used simultaneously with DOGE. Omitted from auto-detect.
        };

        // LTC identification (for swap detection)
        static const std::vector<std::string> LTC_HRPS = {"ltc", "tltc"};
        static const std::vector<uint8_t> LTC_VERSIONS = {0x30, 0x32, 0x05, 0x6f, 0xc4, 0x3a};

        std::string merged_addr_raw;
        parse_address_separators(username_, merged_addr_raw);

        // Resolve simple-separator merged address to chain_id
        if (!merged_addr_raw.empty()) {
            bool resolved = false;

            // Try each configured merged chain
            for (const auto& chain : MERGED_CHAINS) {
                if (mining_interface_ && mining_interface_->has_merged_chain(chain.chain_id) &&
                    is_address_for_chain(merged_addr_raw, chain.hrps, chain.versions)) {
                    merged_addresses_[chain.chain_id] = merged_addr_raw;
                    resolved = true;
                    break;
                }
            }

            // Swap detection: first addr matches a merged chain, second is LTC
            if (!resolved) {
                for (const auto& chain : MERGED_CHAINS) {
                    if (mining_interface_ && mining_interface_->has_merged_chain(chain.chain_id) &&
                        is_address_for_chain(username_, chain.hrps, chain.versions) &&
                        is_address_for_chain(merged_addr_raw, LTC_HRPS, LTC_VERSIONS)) {
                        LOG_WARNING << "[Stratum] Detected swapped address order — auto-correcting.";
                        std::string merged_addr = username_;
                        username_ = merged_addr_raw;
                        merged_addresses_[chain.chain_id] = merged_addr;
                        resolved = true;
                        break;
                    }
                }
            }

            // Fallback: assign to first configured merged chain
            if (!resolved) {
                std::string mtype;
                auto mh = address_to_hash160(merged_addr_raw, mtype);
                if (mh.size() == 40 && mining_interface_) {
                    for (const auto& chain : MERGED_CHAINS) {
                        if (mining_interface_->has_merged_chain(chain.chain_id)) {
                            merged_addresses_[chain.chain_id] = merged_addr_raw;
                            LOG_INFO << "[Stratum] Assigned merged address to chain_id=" << chain.chain_id;
                            resolved = true;
                            break;
                        }
                    }
                }
            }
        }
        if (!merged_addresses_.empty())
            LOG_INFO << "[Stratum] Merged addresses from login: " << merged_addresses_.size() << " chain(s)";

        LOG_INFO << "[Stratum] Mining authorization successful for: " << username_;

        // Auto-derive: for each configured merged chain without an explicit address,
        // reuse the LTC address (works when chains share hash160 format).
        if (mining_interface_) {
            std::string atype;
            auto h160 = address_to_hash160(username_, atype);
            // Store pubkey_hash for per-address hashrate aggregation
            // p2pool: get_local_addr_rates uses pubkey_hash as key
            if (h160.size() == 40) {
                auto h160_bytes = ParseHex(h160);
                if (h160_bytes.size() == 20)
                    std::copy(h160_bytes.begin(), h160_bytes.end(), pubkey_hash_.begin());
            }
            if (h160.size() == 40 && (atype == "p2pkh" || atype == "p2wpkh" || atype == "p2sh")) {
                for (const auto& chain : MERGED_CHAINS) {
                    if (mining_interface_->has_merged_chain(chain.chain_id) &&
                        merged_addresses_.find(chain.chain_id) == merged_addresses_.end()) {
                        merged_addresses_[chain.chain_id] = username_;
                        LOG_INFO << "[Stratum] Auto-derived merged address for chain_id="
                                 << chain.chain_id << " from LTC address";
                    }
                }
            }
        }

        // If merged addresses were parsed (or auto-generated), resend work notification so the
        // coinbase ref_hash includes them.  The initial job sent right after
        // subscribe had empty merged_addresses because authorize hadn't run yet.
        if (!merged_addresses_.empty() && mining_interface_) {
            send_notify_work(true);  // force clean_jobs so miner drops old job without merged_addrs
        }
        
        // Start periodic work push (every SHARE_PERIOD) to keep miner on fresh work
        start_periodic_work_push();

        // Register this session in the worker tracker
        if (mining_interface_) {
            MiningInterface::WorkerInfo wi;
            wi.username = username_;
            wi.difficulty = hashrate_tracker_.get_current_difficulty();
            wi.connected_at = connected_at_;
            try {
                wi.remote_endpoint = socket_.remote_endpoint().address().to_string()
                    + ":" + std::to_string(socket_.remote_endpoint().port());
            } catch (...) {}
            mining_interface_->register_stratum_worker(session_id_, wi);
        }
        
        nlohmann::json response;
        response["id"] = request_id;
        response["result"] = true;
        response["error"] = nullptr;
        
        return response;
    } else {
        nlohmann::json response;
        response["id"] = request_id;
        response["result"] = false;
        response["error"] = nlohmann::json::array({21, "Invalid username", nullptr});
        
        return response;
    }
}

// ═══════════════════════════════════════════════════════════════════
// BIP 310: mining.configure — extension negotiation
// ═══════════════════════════════════════════════════════════════════
// params: [["version-rolling", "subscribe-extranonce", ...], {"version-rolling.mask": "1fffe000", ...}]
// Returns: {"version-rolling": true, "version-rolling.mask": "1fffe000", "subscribe-extranonce": true}
//
// Coinbase safety: version-rolling only touches block header version bits.
// subscribe-extranonce enables mining.set_extranonce notifications —
// extranonce1/2 are in the OP_RETURN output (last 8 bytes), completely
// separate from the scriptSig where merged mining markers (fabe6d6d) live.
nlohmann::json StratumSession::handle_configure(const nlohmann::json& params, const nlohmann::json& request_id)
{
    nlohmann::json result = nlohmann::json::object();

    if (params.size() < 2 || !params[0].is_array() || !params[1].is_object()) {
        nlohmann::json response;
        response["id"] = request_id;
        response["result"] = result;
        response["error"] = nullptr;
        return response;
    }

    const auto& extensions = params[0];
    const auto& ext_params = params[1];

    for (const auto& ext : extensions) {
        if (!ext.is_string()) continue;
        std::string ext_name = ext.get<std::string>();

        if (ext_name == "version-rolling") {
            // Miner provides its mask and optional min-bit-count
            std::string miner_mask_hex = "ffffffff";
            if (ext_params.contains("version-rolling.mask") && ext_params["version-rolling.mask"].is_string())
                miner_mask_hex = ext_params["version-rolling.mask"].get<std::string>();

            uint32_t miner_mask = 0;
            try {
                miner_mask = static_cast<uint32_t>(std::stoul(miner_mask_hex, nullptr, 16));
            } catch (...) {
                LOG_WARNING << "[Stratum] Invalid version-rolling.mask from miner: " << miner_mask_hex;
                miner_mask = 0;
            }

            // Negotiated mask = intersection of pool and miner masks
            version_rolling_mask_ = POOL_VERSION_MASK & miner_mask;
            version_rolling_enabled_ = true;

            std::ostringstream mask_ss;
            mask_ss << std::hex << std::setw(8) << std::setfill('0') << version_rolling_mask_;

            result["version-rolling"] = true;
            result["version-rolling.mask"] = mask_ss.str();

            LOG_INFO << "[Stratum] Version-rolling enabled, negotiated mask: " << mask_ss.str()
                     << " (pool=" << std::hex << POOL_VERSION_MASK
                     << ", miner=" << miner_mask << ")" << std::dec;

        } else if (ext_name == "subscribe-extranonce") {
            // BIP 310 extranonce subscription — enables mining.set_extranonce notifications
            extranonce_subscribe_ = true;
            result["subscribe-extranonce"] = true;
            LOG_INFO << "[Stratum] Extranonce subscription enabled (BIP 310)";

        } else if (ext_name == "minimum-difficulty") {
            // Optional extension — not implemented but acknowledge it
            result["minimum-difficulty"] = false;
        }
    }

    nlohmann::json response;
    response["id"] = request_id;
    response["result"] = result;
    response["error"] = nullptr;
    return response;
}

// ═══════════════════════════════════════════════════════════════════
// NiceHash: mining.extranonce.subscribe — extranonce change subscription
// ═══════════════════════════════════════════════════════════════════
// params: [] (no params)
// Returns: true
// After this, the server may send mining.set_extranonce notifications.
nlohmann::json StratumSession::handle_extranonce_subscribe(const nlohmann::json& params, const nlohmann::json& request_id)
{
    extranonce_subscribe_ = true;
    LOG_INFO << "[Stratum] Extranonce subscription enabled (NiceHash protocol)";

    nlohmann::json response;
    response["id"] = request_id;
    response["result"] = true;
    response["error"] = nullptr;
    return response;
}

// ═══════════════════════════════════════════════════════════════════
// mining.suggest_difficulty — miner suggests initial difficulty
// ═══════════════════════════════════════════════════════════════════
// params: [difficulty] (number)
// Returns: true
// The pool may use this as a hint for the initial set_difficulty.
// If received BEFORE subscribe, we use it as starting difficulty.
// If received AFTER, it feeds into VARDIFF as a hint.
nlohmann::json StratumSession::handle_suggest_difficulty(const nlohmann::json& params, const nlohmann::json& request_id)
{
    double suggested = 0.0;
    if (!params.empty()) {
        if (params[0].is_number())
            suggested = params[0].get<double>();
        else if (params[0].is_string()) {
            try { suggested = std::stod(params[0].get<std::string>()); } catch (...) {}
        }
    }

    if (suggested > 0.0) {
        // Miners send Scrypt difficulty (multiplied by 65536).
        // Convert to internal difficulty for the tracker.
        double internal_diff = suggested / 65536.0;
        suggested_difficulty_ = internal_diff;
        // If already subscribed, apply immediately via VARDIFF hint
        if (subscribed_) {
            hashrate_tracker_.set_difficulty_hint(internal_diff);
            send_set_difficulty(hashrate_tracker_.get_current_difficulty());
        }
        LOG_INFO << "[Stratum] Miner suggested difficulty: " << suggested
                 << " (internal: " << internal_diff << ")";
    }

    nlohmann::json response;
    response["id"] = request_id;
    response["result"] = true;
    response["error"] = nullptr;
    return response;
}

// ═══════════════════════════════════════════════════════════════════
// mining.set_extranonce notification (server → client)
// ═══════════════════════════════════════════════════════════════════
// Sent to miners that subscribed via mining.configure(subscribe-extranonce)
// or mining.extranonce.subscribe.
//
// Coinbase safety analysis:
//   - extranonce1/2 occupy the LAST 8 bytes of the OP_RETURN output
//   - They are NOT in the scriptSig (where merged mining fabe6d6d markers live)
//   - Changing extranonce1 requires rebuilding coinb1/coinb2 (which includes ref_hash)
//   - We MUST send clean_jobs=true after set_extranonce to invalidate old jobs
//   - The atomic counter in generate_extranonce1() prevents collisions
void StratumSession::send_set_extranonce(const std::string& extranonce1, int extranonce2_size)
{
    nlohmann::json notification;
    notification["id"] = nullptr;
    notification["method"] = "mining.set_extranonce";
    notification["params"] = nlohmann::json::array({extranonce1, extranonce2_size});

    send_response(notification);
}

// mining.set_merged_addresses extension
// params: [{ "chain_id": "address", ... }]  — keys are chain_id as strings
// Example: [{"98": "DQkwFoo...", "2": "1btcAddr..."}]
nlohmann::json StratumSession::handle_set_merged_addresses(const nlohmann::json& params, const nlohmann::json& request_id)
{
    if (params.empty() || !params[0].is_object()) {
        nlohmann::json response;
        response["id"] = request_id;
        response["result"] = false;
        response["error"] = nlohmann::json::array({20, "Expected object param {chain_id: address}", nullptr});
        return response;
    }

    for (auto& [key, val] : params[0].items()) {
        if (val.is_string()) {
            try {
                uint32_t chain_id = static_cast<uint32_t>(std::stoul(key));
                merged_addresses_[chain_id] = val.get<std::string>();
            } catch (...) {
                // skip malformed
            }
        }
    }

    LOG_INFO << "Set merged addresses for " << username_ << ": " << merged_addresses_.size() << " chain(s)";

    nlohmann::json response;
    response["id"] = request_id;
    response["result"] = true;
    response["error"] = nullptr;
    return response;
}

nlohmann::json StratumSession::handle_submit(const nlohmann::json& params, const nlohmann::json& request_id)
{
    if (!authorized_) {
        nlohmann::json response;
        response["id"] = request_id;
        response["result"] = false;
        response["error"] = nlohmann::json::array({24, "Unauthorized", nullptr});
        return response;
    }
    
    // Extract Stratum submit parameters: [username, job_id, extranonce2, ntime, nonce]
    if (params.size() < 5 || !params[1].is_string() || !params[2].is_string()
        || !params[3].is_string() || !params[4].is_string()) {
        ++rejected_shares_;
        nlohmann::json response;
        response["id"] = request_id;
        response["result"] = false;
        response["error"] = nlohmann::json::array({20, "Invalid parameters", nullptr});
        return response;
    }
    
    std::string job_id      = params[1].get<std::string>();
    std::string extranonce2 = params[2].get<std::string>();
    std::string ntime       = params[3].get<std::string>();
    std::string nonce       = params[4].get<std::string>();

    // ASICBoost: optional 6th parameter is version_bits (hex mask of rolled bits)
    std::string version_bits;
    if (params.size() >= 6 && params[5].is_string())
        version_bits = params[5].get<std::string>();

    // Stale detection: check if job_id is still active.
    auto job_it = active_jobs_.find(job_id);
    bool is_stale = (job_it == active_jobs_.end());
    if (is_stale) {
        ++stale_shares_;
        LOG_INFO << "[Stratum] Stale share from " << username_ << " for expired job " << job_id
                 << " (active_jobs=" << active_jobs_.size() << ")";
        // Job data evicted — can't reconstruct block or share.
        // Return stale response to the miner.
        nlohmann::json response;
        response["id"] = request_id;
        response["result"] = false;
        response["error"] = nlohmann::json::array({21, "Stale share", nullptr});
        return response;
    }

    // DOA detection: if GBT previousblockhash changed since job creation,
    // this share is for an old block. Track for statistics but do NOT modify
    // job.stale_info — that field is part of ref_hash (frozen at template time).
    // Changing it at submit time would break ref_hash consistency → GENTX-FAIL.
    // p2pool computes stale_info at get_work() time (job creation), not at submit.
    {
        auto current_prevhash = mining_interface_->get_current_gbt_prevhash();
        if (!current_prevhash.empty() && !job_it->second.gbt_prevhash.empty()
            && current_prevhash != job_it->second.gbt_prevhash)
        {
            LOG_INFO << "[Stratum] DOA share from " << username_
                     << ": block template changed (job=" << job_id
                     << " job_prev=" << job_it->second.gbt_prevhash.substr(0, 16)
                     << " current_prev=" << current_prevhash.substr(0, 16) << ")";
            // DON'T set job.stale_info here — it would break ref_hash.
            // The share is still created and broadcast (matches p2pool behavior).
            // DOA tracking is for statistics/dashboard only.
        }
    }
    
    // Calculate share difficulty using per-connection coinbase and job-specific template data
    const auto& job = job_it->second;

    // ASICBoost: apply version rolling bits to the job version
    uint32_t effective_version = job.version;
    if (version_rolling_enabled_ && !version_bits.empty()) {
        try {
            uint32_t miner_version_bits = static_cast<uint32_t>(std::stoul(version_bits, nullptr, 16));
            // Validate: miner must not modify bits outside the negotiated mask
            if ((~version_rolling_mask_ & miner_version_bits) != 0) {
                ++rejected_shares_;
                LOG_WARNING << "[Stratum] Miner " << username_
                            << " modified version bits outside negotiated mask: "
                            << version_bits << " (mask=" << std::hex << version_rolling_mask_ << ")" << std::dec;
                nlohmann::json response;
                response["id"] = request_id;
                response["result"] = false;
                response["error"] = nlohmann::json::array({20, "Invalid version mask", nullptr});
                return response;
            }
            // Apply: keep non-rolling bits from job, take rolling bits from miner
            effective_version = (job.version & ~version_rolling_mask_) | (miner_version_bits & version_rolling_mask_);
        } catch (...) {
            LOG_WARNING << "[Stratum] Invalid version_bits hex from " << username_ << ": " << version_bits;
        }
    }

    // Use gbt_prevhash (BE display hex) — SetHex converts to LE internal,
    // matching build_block_from_stratum which the daemon accepts.
    double share_difficulty = MiningInterface::calculate_share_difficulty(
        job.coinb1, job.coinb2,
        extranonce1_, extranonce2, ntime, nonce,
        effective_version, job.gbt_prevhash, job.nbits, job.merkle_branches);
    // VARDIFF: acceptance threshold is the per-connection adaptive difficulty.
    // p2pool accepts ALL pseudoshares meeting effective_target (VARDIFF level),
    // not just those meeting pool share_bits. This gives smooth hashrate data.
    double vardiff_difficulty = hashrate_tracker_.get_current_difficulty();

    // Pool share difficulty (for P2P share creation threshold)
    double pool_difficulty = 0.0;
    uint32_t sb = mining_interface_->m_share_bits.load();
    if (sb != 0)
        pool_difficulty = chain::target_to_difficulty(chain::bits_to_target(sb));

    // Use VARDIFF as stratum acceptance threshold
    double required_difficulty = vardiff_difficulty;

    // Build JobSnapshot BEFORE the rejection gate — needed for block-level
    // checking which must run on ALL submissions, not just accepted ones.
    // P2Pool checks every share against the block target regardless of
    // pool-level difficulty acceptance.  Missing this check means ~75% of
    // valid blocks are silently discarded.
    std::map<uint32_t, std::vector<unsigned char>> merged_scripts;
    for (const auto& [chain_id, addr] : merged_addresses_) {
        std::string atype;
        auto h160 = address_to_hash160(addr, atype);
        if (h160.size() == 40) {
            auto script = hash160_to_merged_script(h160, atype);
            if (!script.empty())
                merged_scripts[chain_id] = std::move(script);
        }
    }

    MiningInterface::JobSnapshot snapshot;
    snapshot.coinb1          = job.coinb1;
    snapshot.coinb2          = job.coinb2;
    snapshot.gbt_prevhash    = job.gbt_prevhash;
    snapshot.nbits           = job.nbits;           // share target bits (for header construction)
    snapshot.block_nbits     = job.gbt_block_nbits; // original GBT block bits (for block target check)
    snapshot.version         = effective_version;  // use rolled version for block construction
    snapshot.merkle_branches = job.merkle_branches;
    snapshot.tx_data         = job.tx_data;
    snapshot.mweb            = job.mweb;
    snapshot.segwit_active   = job.segwit_active;
    snapshot.prev_share_hash = job.prev_share_hash;
    snapshot.subsidy         = job.subsidy;
    snapshot.witness_commitment_hex = job.witness_commitment_hex;
    snapshot.witness_root            = job.witness_root;
    snapshot.share_bits      = mining_interface_->m_share_bits.load();
    snapshot.share_max_bits  = mining_interface_->m_share_max_bits.load();
    // Pass frozen share fields through to ShareCreationParams
    snapshot.frozen_ref.absheight = job.frozen_absheight;
    snapshot.frozen_ref.abswork = job.frozen_abswork;
    snapshot.frozen_ref.far_share_hash = job.frozen_far_share_hash;
    snapshot.frozen_ref.max_bits = job.frozen_max_bits;
    snapshot.frozen_ref.bits = job.frozen_bits;
    snapshot.frozen_ref.timestamp = job.frozen_timestamp;
    snapshot.frozen_ref.merged_payout_hash = job.frozen_merged_payout_hash;
    snapshot.frozen_ref.frozen_merkle_branches = job.frozen_merkle_branches;
    snapshot.frozen_ref.frozen_witness_root = job.frozen_witness_root;
    snapshot.frozen_ref.frozen_merged_coinbase_info = job.frozen_merged_coinbase_info;
    // NOTE: stale_info is NOT propagated here. It must match what ref_hash_fn
    // used at job creation time (always 0 for now). Changing it at submit
    // time would break ref_hash consistency. Future: compute stale_info
    // at ref_hash_fn time and freeze it, matching p2pool's get_work() pattern.

    // ── Pseudoshare acceptance gate (VARDIFF level) ──
    // p2pool accepts ALL submissions meeting effective_target (VARDIFF).
    // Below VARDIFF → reject. Above VARDIFF → pseudoshare (record for hashrate).
    // Above pool target → also a P2P share (broadcast to network).
    if (share_difficulty < required_difficulty) {
        ++rejected_shares_;
        // Record rejection for VARDIFF timing (p2pool only records accepted,
        // but we need the timing signal to avoid stalling VARDIFF).
        hashrate_tracker_.record_mining_share_submission(vardiff_difficulty, false);
        nlohmann::json response;
        response["id"] = request_id;
        response["result"] = false;
        response["error"] = nlohmann::json::array({23, "Low difficulty share", nullptr});
        return response;
    }

    // ── Pseudoshare accepted — record in RateMonitor ──
    // p2pool: work = target_to_average_attempts(effective_target)
    // For us: work = vardiff_difficulty × 2^32 (equivalent unit conversion)
    ++accepted_shares_;
    static constexpr double TWO_32 = 4294967296.0;
    double work = vardiff_difficulty * TWO_32;
    bool is_dead = (job.stale_info != 0);

    // Record in global RateMonitor (for get_local_addr_rates)
    if (server_)
        server_->record_pseudoshare(work, pubkey_hash_, username_, is_dead);

    // Record in per-connection tracker (for VARDIFF adjustment + per-session stats)
    hashrate_tracker_.record_mining_share_submission(vardiff_difficulty, true);

    // Check if VARDIFF changed → send new difficulty AND new work to miner.
    // p2pool (stratum.py:594-595): after adjusting target, calls _send_work()
    // which sends both set_difficulty and mining.notify. Without new work,
    // the miner continues hashing at the OLD difficulty until the next natural
    // work refresh, causing VARDIFF oscillation and hashrate undercount.
    if (hashrate_tracker_.difficulty_changed_since(vardiff_difficulty)) {
        double new_diff = hashrate_tracker_.get_current_difficulty();
        send_set_difficulty(new_diff);
        send_notify_work(true);  // p2pool: self._send_work() after VARDIFF
        LOG_INFO << "[Stratum] VARDIFF: " << vardiff_difficulty << " -> " << new_diff
                 << " for " << username_;
    }

    // ── Pool-quality share gate ──
    // Only create P2P share + block check for submissions meeting pool target.
    bool is_pool_share = (pool_difficulty > 0.0 && share_difficulty >= pool_difficulty);
    if (is_pool_share) {
        // Full share creation + block-level PoW check
        mining_interface_->mining_submit(username_, job_id, extranonce1_, extranonce2, ntime, nonce, "", merged_scripts,
            &snapshot);
        LOG_INFO << "[Stratum] P2P share from " << username_ << " (diff=" << share_difficulty
                 << " >= pool=" << pool_difficulty << ")";
    } else {
        // Pseudoshare only — still check for blocks.
        // A pseudoshare can meet the block target on testnet where
        // block_difficulty < vardiff_difficulty.
        double block_difficulty = 0.0;
        if (!job.gbt_block_nbits.empty()) {
            uint32_t block_bits = static_cast<uint32_t>(std::stoul(job.gbt_block_nbits, nullptr, 16));
            block_difficulty = chain::target_to_difficulty(chain::bits_to_target(block_bits));
        }
        if (block_difficulty > 0.0 && share_difficulty >= block_difficulty) {
            // Rare: pseudoshare is a block! Submit it.
            mining_interface_->mining_submit(username_, job_id, extranonce1_, extranonce2, ntime, nonce, "", merged_scripts,
                &snapshot);
            LOG_INFO << "[Stratum] Pseudoshare IS A BLOCK from " << username_
                     << " (diff=" << share_difficulty << " >= block=" << block_difficulty << ")";
        }
    }

    LOG_TRACE << "[Stratum] Pseudoshare accepted from " << username_
              << " (hash_diff=" << share_difficulty << ", vardiff=" << vardiff_difficulty
              << ", pool=" << pool_difficulty
              << ", accepted=" << accepted_shares_ << ", rejected=" << rejected_shares_ << ")";

    // Update worker tracker with latest stats
    if (mining_interface_) {
        mining_interface_->update_stratum_worker(session_id_,
            hashrate_tracker_.get_current_hashrate(),
            0.0,
            hashrate_tracker_.get_current_difficulty(),
            accepted_shares_, rejected_shares_, stale_shares_);
    }

    nlohmann::json response;
    response["id"] = request_id;
    response["result"] = true;
    response["error"] = nullptr;

    return response;
}

void StratumSession::send_response(const nlohmann::json& response)
{
    try {
        std::string message = response.dump() + "\n";
        boost::asio::write(socket_, boost::asio::buffer(message));
    } catch (const std::exception& e) {
        LOG_ERROR << "[Stratum] Error sending response: " << e.what();
    }
}

void StratumSession::send_error(int code, const std::string& message, const nlohmann::json& request_id)
{
    nlohmann::json response;
    response["id"] = request_id;
    response["result"] = nullptr;
    response["error"] = nlohmann::json::array({code, message, nullptr});
    
    send_response(response);
}

void StratumSession::send_set_difficulty(double difficulty)
{
    // Scrypt pools must multiply by DUMB_SCRYPT_DIFF (2^16 = 65536) when
    // sending mining.set_difficulty. Without this, Scrypt miners interpret
    // the difficulty as near-zero and submit all solutions indiscriminately.
    // Reference: p2pool stratum.py line 465:
    //   target_to_difficulty(self.target) * self.wb.net.DUMB_SCRYPT_DIFF
    static constexpr double DUMB_SCRYPT_DIFF = 65536.0;

    nlohmann::json notification;
    notification["id"] = nullptr;
    notification["method"] = "mining.set_difficulty";
    notification["params"] = nlohmann::json::array({difficulty * DUMB_SCRYPT_DIFF});

    LOG_INFO << "[Stratum] set_difficulty: internal=" << difficulty
             << " wire=" << (difficulty * DUMB_SCRYPT_DIFF);
    send_response(notification);
}

// Convert GBT previousblockhash (big-endian display hex) to Stratum prevhash format.
// Stratum prevhash = internal LE bytes with each 4-byte chunk reversed.
static std::string gbt_to_stratum_prevhash(const std::string& gbt_hex)
{
    if (gbt_hex.size() != 64) return gbt_hex;
    // 1. Parse BE hex to bytes
    std::vector<unsigned char> bytes;
    bytes.reserve(32);
    for (size_t i = 0; i < 64; i += 2)
        bytes.push_back(static_cast<unsigned char>(
            std::stoul(gbt_hex.substr(i, 2), nullptr, 16)));
    // 2. Reverse to get internal LE  
    std::reverse(bytes.begin(), bytes.end());
    // 3. Reverse each 4-byte chunk
    for (int i = 0; i < 32; i += 4)
        std::reverse(bytes.begin() + i, bytes.begin() + i + 4);
    // 4. Hex encode
    static const char* HEX = "0123456789abcdef";
    std::string result;
    result.reserve(64);
    for (unsigned char b : bytes) {
        result += HEX[b >> 4];
        result += HEX[b & 0x0f];
    }
    return result;
}

void StratumSession::send_notify_work(bool force_clean)
{
    // Don't send work until a valid block template is available
    auto tmpl = mining_interface_->get_current_work_template();
    if (tmpl.empty() || tmpl.is_null()) {
        // Rate-limit "no template" log to avoid spam during header sync
        static std::atomic<int64_t> s_last_warn{0};
        auto now = std::chrono::steady_clock::now().time_since_epoch().count();
        auto prev = s_last_warn.load();
        if (now - prev > 30'000'000'000LL) { // 30 seconds
            if (s_last_warn.compare_exchange_strong(prev, now))
                LOG_WARNING << "[LTC] Waiting for block template (header sync in progress)...";
        }
        auto timer = std::make_shared<boost::asio::steady_timer>(socket_.get_executor());
        timer->expires_after(std::chrono::seconds(1));
        timer->async_wait([this, self = shared_from_this(), timer](boost::system::error_code ec) {
            if (!ec) send_notify_work();
        });
        return;
    }

    nlohmann::json notification;
    notification["id"] = nullptr;
    notification["method"] = "mining.notify";

    std::string job_id  = "job_" + std::to_string(job_counter_.fetch_add(1));

    std::string prevhash;
    std::string gbt_prevhash;
    std::string version;
    uint32_t    version_u32;
    std::string nbits;
    uint32_t    curtime  = static_cast<uint32_t>(std::time(nullptr));
    nlohmann::json merkle_branches = nlohmann::json::array();
    std::vector<std::string> merkle_branches_vec;
    std::string coinb1 = "01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff";
    std::string coinb2 = "0000000000f2052a010000001976a914000000000000000000000000000000000000000088ac00000000";
    std::string gbt_block_nbits;  // original GBT block bits (preserved for block-level target check)

    // Populate from live block template
    {
        gbt_prevhash = tmpl.value("previousblockhash", "");
        prevhash = gbt_to_stratum_prevhash(gbt_prevhash);

        version_u32 = static_cast<uint32_t>(tmpl.value("version", 0x20000000));
        std::ostringstream ss;
        ss << std::hex << std::setw(8) << std::setfill('0')
           << version_u32;
        version = ss.str();

        // Save original GBT block bits for block-level target check
        if (tmpl.contains("bits"))
            gbt_block_nbits = tmpl["bits"].get<std::string>();
        else
            gbt_block_nbits = "1d00ffff";

        // nbits in mining.notify = GBT BLOCK difficulty (not share target).
        // p2pool sends block_bits here. The miner puts this in the 80-byte header's
        // nBits field. The share difficulty is communicated separately via
        // mining.set_difficulty (VARDIFF). This is critical for interoperability:
        // p2pool stores min_header.bits = header.bits = GBT block bits.
        nbits = gbt_block_nbits;

        if (tmpl.contains("curtime"))
            curtime = static_cast<uint32_t>(tmpl["curtime"].get<uint64_t>());

        LOG_TRACE << "[Stratum] send_notify_work: height="
                  << tmpl.value("height", 0) << " prevhash=" << prevhash
                  << " nbits=" << nbits;
    }

    // Encode curtime as 8-hex-char (4-byte big-endian)
    std::ostringstream ntime_ss;
    ntime_ss << std::hex << std::setw(8) << std::setfill('0') << curtime;
    std::string ntime = ntime_ss.str();

    // Merkle branches
    merkle_branches_vec = mining_interface_->get_stratum_merkle_branches();
    for (const auto& h : merkle_branches_vec)
        merkle_branches.push_back(h);

    // Per-connection coinbase: build with ref_hash from this session's extranonce1
    // This ensures the OP_RETURN commitment matches this miner's specific coinbase.
    // Freeze share chain tip ONCE — used for both ref_hash computation
    // and the job's stored prev_share_hash to avoid race conditions.
    // p2pool: previous_share_hash = self.node.best_share_var.value
    // Uses best_share directly — no peer filtering.
    // think() Phase 5 (punish walk + best_descendent) ensures best is correct.
    uint256 frozen_prev_share;
    MiningInterface::CoinbaseResult cbr;
    if (auto fn = mining_interface_->get_best_share_hash_fn())
        frozen_prev_share = fn();
    {
        // Build payout script from username (authorized address: P2PKH, P2SH, or bech32)
        std::vector<unsigned char> payout_script;
        if (!username_.empty()) {
            payout_script = address_to_script(username_);
        }

        // Build merged address entries (bech32+base58, P2PKH+P2SH)
        std::vector<std::pair<uint32_t, std::vector<unsigned char>>> merged_addrs;
        for (const auto& [chain_id, addr] : merged_addresses_) {
            std::string atype;
            auto h160 = address_to_hash160(addr, atype);
            if (h160.size() == 40) {
                auto script = hash160_to_merged_script(h160, atype);
                if (!script.empty())
                    merged_addrs.push_back({chain_id, std::move(script)});
            }
        }

        cbr = mining_interface_->build_connection_coinbase(
            frozen_prev_share, extranonce1_, payout_script, merged_addrs);
        if (!cbr.coinb1.empty()) {
            coinb1 = std::move(cbr.coinb1);
            coinb2 = std::move(cbr.coinb2);
        } else {
            // Fallback to global coinbase (no ref_hash callback wired)
            auto [gcb1, gcb2] = mining_interface_->get_coinbase_parts();
            if (!gcb1.empty()) {
                coinb1 = std::move(gcb1);
                coinb2 = std::move(gcb2);
            }
        }
    }

    // clean_jobs = true when prevhash changed OR forced (e.g. after authorize)
    bool clean_jobs = force_clean || (prevhash != last_prevhash_);
    last_prevhash_ = prevhash;

    // Track this job — evict oldest if at capacity (keep MAX_ACTIVE_JOBS for late shares)
    while (active_jobs_.size() >= MAX_ACTIVE_JOBS) {
        active_jobs_.erase(active_jobs_.begin());
    }
    {
        JobEntry je;
        je.prevhash = prevhash;
        je.gbt_prevhash = gbt_prevhash;
        je.nbits = nbits;
        je.ntime = curtime;
        je.coinb1 = coinb1;
        je.coinb2 = coinb2;
        je.version = version_u32;
        je.merkle_branches = merkle_branches_vec;
        je.gbt_block_nbits = gbt_block_nbits;
        active_jobs_[job_id] = std::move(je);
    }

    // Store the SAME frozen prev_share_hash that was used for ref_hash computation
    active_jobs_[job_id].prev_share_hash = frozen_prev_share;

    // Populate tx_data, mweb, segwit_active, subsidy, witness_commitment from snapshot.
    // CRITICAL: witness_commitment and witness_root MUST be read atomically with
    // the coinbase parts (coinb1 contains the witness commitment bytes).
    // We snapshot them under the work mutex via get_work_snapshot() to prevent
    // refresh_work() from changing them between coinbase build and job storage.
    {
        auto& je = active_jobs_[job_id];
        // Use the snapshot captured atomically with coinbase parts
        // to prevent race with refresh_work() changing witness data.
        je.segwit_active = cbr.snapshot.segwit_active;
        je.mweb = std::move(cbr.snapshot.mweb);
        je.subsidy = cbr.snapshot.subsidy;
        je.witness_commitment_hex = std::move(cbr.snapshot.witness_commitment_hex);
        je.witness_root = cbr.snapshot.witness_root;
        je.frozen_absheight = cbr.snapshot.frozen_ref.absheight;
        je.frozen_abswork = cbr.snapshot.frozen_ref.abswork;
        je.frozen_far_share_hash = cbr.snapshot.frozen_ref.far_share_hash;
        je.frozen_max_bits = cbr.snapshot.frozen_ref.max_bits;
        je.frozen_bits = cbr.snapshot.frozen_ref.bits;
        je.frozen_timestamp = cbr.snapshot.frozen_ref.timestamp;
        je.frozen_merged_payout_hash = cbr.snapshot.frozen_ref.merged_payout_hash;
        je.frozen_merkle_branches = cbr.snapshot.frozen_ref.frozen_merkle_branches;
        je.frozen_witness_root = cbr.snapshot.frozen_ref.frozen_witness_root;
        je.frozen_merged_coinbase_info = cbr.snapshot.frozen_ref.frozen_merged_coinbase_info;
        je.has_frozen = true;

        if (!tmpl.empty() && !tmpl.is_null() && tmpl.contains("transactions")) {
            for (const auto& tx : tmpl["transactions"]) {
                if (tx.contains("data"))
                    je.tx_data.push_back(tx["data"].get<std::string>());
            }
        }
    }

    // VARDIFF: do NOT override per-connection difficulty with pool share_bits.
    // p2pool sends pseudoshare difficulty (VARDIFF) to miners, NOT pool target.
    // Miners submit many pseudoshares at low difficulty; only those meeting
    // share_bits become P2P shares. This gives smooth hashrate estimation.
    // VARDIFF adjustment happens in handle_submit after each pseudoshare.

    notification["params"] = nlohmann::json::array({
        job_id, prevhash, coinb1, coinb2, merkle_branches,
        version, nbits, ntime, clean_jobs
    });

    send_response(notification);
}

void StratumSession::start_periodic_work_push()
{
    work_push_timer_ = std::make_shared<boost::asio::steady_timer>(socket_.get_executor());
    auto self = shared_from_this();
    auto fn = std::make_shared<std::function<void(boost::system::error_code)>>();
    *fn = [this, self, fn](boost::system::error_code ec) {
        if (ec) return;
        send_notify_work();
        // Push new work every 4 seconds — matches p2pool's natural share rate.
        // Too frequent pushes cause high stale rate on slow ASIC miners.
        work_push_timer_->expires_after(std::chrono::seconds(4));
        work_push_timer_->async_wait(*fn);
    };
    work_push_timer_->expires_after(std::chrono::seconds(1));
    work_push_timer_->async_wait(*fn);
}

// Parse multi-chain addresses from username string.
// Tries multiple separator formats for maximum miner compatibility:
//   1. Slash+colon: "LTC_ADDR/98:DOGE_ADDR"  (explicit chain ID)
//   2. Comma:       "LTC_ADDR,DOGE_ADDR"      (standard)
//   3. Pipe:        "LTC_ADDR|DOGE_ADDR"       (Vnish firmware)
//   4. Semicolon:   "LTC_ADDR;DOGE_ADDR"       (alternative)
//   5. Space:       "LTC_ADDR DOGE_ADDR"        (some web UIs)
//
// Slash format populates merged_addresses_ directly.
// Simple formats extract merged_addr_raw for chain auto-detection.
void StratumSession::parse_address_separators(std::string& username, std::string& merged_addr_raw)
{
    // Priority 1: Slash format with explicit chain IDs
    auto slash_pos = username.find('/');
    if (slash_pos != std::string::npos) {
        std::string remainder = username.substr(slash_pos + 1);
        username = username.substr(0, slash_pos);
        std::istringstream ss(remainder);
        std::string token;
        while (std::getline(ss, token, '/')) {
            auto colon = token.find(':');
            if (colon != std::string::npos && colon > 0 && colon + 1 < token.size()) {
                try {
                    uint32_t chain_id = static_cast<uint32_t>(std::stoul(token.substr(0, colon)));
                    merged_addresses_[chain_id] = token.substr(colon + 1);
                } catch (...) {}
            }
        }
        return;
    }

    // Priority 2-5: Simple two-address separators (comma, pipe, semicolon, space)
    // Try each in order; first match wins.
    for (char sep : {',', '|', ';', ' '}) {
        auto sep_pos = username.find(sep);
        if (sep_pos != std::string::npos && sep_pos > 20) {
            merged_addr_raw = username.substr(sep_pos + 1);
            username = username.substr(0, sep_pos);
            // Strip worker name from merged address too
            auto mdot = merged_addr_raw.rfind('.');
            if (mdot != std::string::npos && mdot > 20) merged_addr_raw = merged_addr_raw.substr(0, mdot);
            auto mus = merged_addr_raw.rfind('_');
            if (mus != std::string::npos && mus > 20) merged_addr_raw = merged_addr_raw.substr(0, mus);

            if (sep != ',')
                LOG_INFO << "[Stratum] Parsed merged address using '" << sep << "' separator";
            return;
        }
    }
}

std::string StratumSession::generate_extranonce1()
{
    static std::atomic<uint32_t> extranonce_counter{0};
    uint32_t value = extranonce_counter.fetch_add(1);
    std::stringstream ss;
    ss << std::hex << std::setw(8) << std::setfill('0') << value;
    return ss.str();
}

} // namespace core

