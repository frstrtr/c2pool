#include "web_server.hpp"
#include "cookie_auth.hpp"
#include "runtime_config.hpp"

// Real coin daemon RPC (optional - only linked when set_coin_rpc() is called)
#include <impl/ltc/coin/rpc.hpp>
#include <impl/ltc/coin/node_interface.hpp>
#include <impl/ltc/share_messages.hpp>

#include <core/hash.hpp>   // Hash(a,b) double-SHA256 for merkle computation
#include <core/random.hpp> // core::random::random_float for probabilistic fee
#include <core/target_utils.hpp> // chain::bits_to_target
#include <btclibs/util/strencodings.h>  // ParseHex, HexStr
#include <crypto/scrypt.h>  // scrypt_1024_1_1_256 for Litecoin PoW
#include <c2pool/merged/merged_mining.hpp>  // Integrated merged mining

#include <iomanip>
#include <sstream>
#include <ctime>
#include <chrono>
#include <cmath>
#include <fstream>
#include <boost/process.hpp>
#include <boost/algorithm/string.hpp>
#include "btclibs/base58.h"
#include "btclibs/bech32.h"
#include "filesystem.hpp"

namespace core {

static std::string to_hex(const std::vector<unsigned char>& data)
{
    return HexStr(std::span<const unsigned char>(data.data(), data.size()));
}

/// Static member definition
std::atomic<uint64_t> StratumSession::job_counter_{0};

/// HttpSession Implementation
HttpSession::HttpSession(tcp::socket socket, std::shared_ptr<MiningInterface> mining_interface)
    : socket_(std::move(socket))
    , mining_interface_(mining_interface)
{
}

void HttpSession::run()
{
    read_request();
}

void HttpSession::read_request()
{
    auto self = shared_from_this();
    
    http::async_read(socket_, buffer_, request_,
        [self](beast::error_code ec, std::size_t bytes_transferred)
        {
            boost::ignore_unused(bytes_transferred);
            
            if(ec == http::error::end_of_stream)
                return self->handle_error(ec, "read_request");
                
            if(ec)
                return self->handle_error(ec, "read_request");
                
            self->process_request();
        });
}

void HttpSession::process_request()
{
    // Create HTTP response
    http::response<http::string_body> response{http::status::ok, request_.version()};
    response.set(http::field::server, "c2pool/0.0.1");
    response.set(http::field::content_type, "application/json");
    response.set(http::field::access_control_allow_origin, "*");
    response.set(http::field::access_control_allow_methods, "GET, POST, OPTIONS");
    response.set(http::field::access_control_allow_headers, "Content-Type");

    try {
        std::string response_body;
        
        if (request_.method() == http::verb::options) {
            // Handle CORS preflight
            response_body = "";
        }
        else if (request_.method() == http::verb::get) {
            // Path-based REST routing for p2pool-compatible endpoints
            std::string raw_target(request_.target());
            std::string target(raw_target);
            // Strip query string
            auto qpos = target.find('?');
            if (qpos != std::string::npos) target = target.substr(0, qpos);

            auto getQueryParam = [&raw_target](const std::string& key) -> std::string {
                const auto qp = raw_target.find('?');
                if (qp == std::string::npos) {
                    return {};
                }
                const std::string query = raw_target.substr(qp + 1);
                const std::string prefix = key + "=";
                auto pos = query.find(prefix);
                if (pos == std::string::npos) {
                    return {};
                }
                pos += prefix.size();
                auto end = query.find('&', pos);
                if (end == std::string::npos) {
                    end = query.size();
                }
                return query.substr(pos, end - pos);
            };

            nlohmann::json rest_result;
            if (target == "/local_rate")
                rest_result = mining_interface_->rest_local_rate();
            else if (target == "/global_rate")
                rest_result = mining_interface_->rest_global_rate();
            else if (target == "/current_payouts")
                rest_result = mining_interface_->rest_current_payouts();
            else if (target == "/users")
                rest_result = mining_interface_->rest_users();
            else if (target == "/fee")
                rest_result = mining_interface_->rest_fee();
            else if (target == "/recent_blocks")
                rest_result = mining_interface_->rest_recent_blocks();
            else if (target == "/uptime")
                rest_result = mining_interface_->rest_uptime();
            else if (target == "/connected_miners")
                rest_result = mining_interface_->rest_connected_miners();
            else if (target == "/stratum_stats")
                rest_result = mining_interface_->rest_stratum_stats();
            else if (target == "/global_stats")
                rest_result = mining_interface_->rest_global_stats();
            else if (target == "/sharechain/stats")
                rest_result = mining_interface_->rest_sharechain_stats();
            else if (target == "/sharechain/window")
                rest_result = mining_interface_->rest_sharechain_window();
            else if (target == "/config" || target.starts_with("/control/") ||
                     target == "/web/log" || target == "/logs/export") {
                // Auth-protected endpoints: validate cookie token
                const std::string token = getQueryParam("token");
                const bool auth_ok = CookieAuth::active_cookie().empty() || CookieAuth::validate(token);
                if (!auth_ok) {
                    response.result(http::status::unauthorized);
                    response.body() = R"({"error":"unauthorized","message":"invalid or missing auth token"})";
                    response.prepare_payload();
                    send_response(std::move(response));
                    return;
                }

                if (target == "/config") {
                    rest_result = mining_interface_->rest_config();
                } else if (target == "/control/mining/start")
                    rest_result = mining_interface_->rest_control_mining_start();
                else if (target == "/control/mining/stop")
                    rest_result = mining_interface_->rest_control_mining_stop();
                else if (target == "/control/mining/restart")
                    rest_result = mining_interface_->rest_control_mining_restart();
                else if (target == "/control/mining/ban")
                    rest_result = mining_interface_->rest_control_mining_ban(getQueryParam("target"));
                else if (target == "/control/mining/unban")
                    rest_result = mining_interface_->rest_control_mining_unban(getQueryParam("target"));
                else if (target == "/web/log") {
                    response.set(http::field::content_type, "text/plain; charset=utf-8");
                    response.body() = mining_interface_->rest_web_log();
                    response.prepare_payload();
                    send_response(std::move(response));
                    return;
                }
                else if (target == "/logs/export") {
                    const std::string scope = getQueryParam("scope");
                    int64_t from_ts = 0, to_ts = 0;
                    try { from_ts = std::stoll(getQueryParam("from")); } catch (...) {}
                    try { to_ts = std::stoll(getQueryParam("to")); } catch (...) {}
                    const std::string fmt = getQueryParam("format");
                    response.set(http::field::content_type,
                        (fmt == "csv") ? "text/csv; charset=utf-8" :
                        (fmt == "jsonl") ? "application/x-ndjson; charset=utf-8" :
                        "text/plain; charset=utf-8");
                    response.body() = mining_interface_->rest_logs_export(scope, from_ts, to_ts, fmt);
                    response.prepare_payload();
                    send_response(std::move(response));
                    return;
                }
            } // end auth-protected block
            else
                rest_result = mining_interface_->getinfo();

            response_body = rest_result.dump();
        }
        else if (request_.method() == http::verb::post) {
            // Handle JSON-RPC POST request
            std::string request_body = request_.body();
            LOG_DEBUG_DIAG << "Received JSON-RPC request: " << request_body;
            
            response_body = mining_interface_->HandleRequest(request_body);
            
            LOG_DEBUG_DIAG << "Sending JSON-RPC response: " << response_body;
        }
        else {
            response.result(http::status::method_not_allowed);
            response_body = R"({"error":"Method not allowed"})";
        }
        
        response.body() = response_body;
        response.prepare_payload();
        
    } catch (const std::exception& e) {
        LOG_ERROR << "Error processing request: " << e.what();
        response.result(http::status::internal_server_error);
        response.body() = R"({"error":"Internal server error"})";
        response.prepare_payload();
    }
    
    send_response(std::move(response));
}

void HttpSession::send_response(http::response<http::string_body> response)
{
    auto self = shared_from_this();
    
    auto response_ptr = std::make_shared<http::response<http::string_body>>(std::move(response));
    
    http::async_write(socket_, *response_ptr,
        [self, response_ptr](beast::error_code ec, std::size_t bytes_transferred)
        {
            boost::ignore_unused(bytes_transferred);
            
            if(ec)
                return self->handle_error(ec, "send_response");
                
            // Gracefully close the connection
            beast::error_code close_ec;
            self->socket_.shutdown(tcp::socket::shutdown_send, close_ec);
        });
}

void HttpSession::handle_error(beast::error_code ec, char const* what)
{
    if (ec != beast::errc::operation_canceled && ec != beast::errc::broken_pipe) {
        LOG_WARNING << "HTTP Session error in " << what << ": " << ec.message();
    }
}

/// MiningInterface Implementation
MiningInterface::MiningInterface(bool testnet, std::shared_ptr<IMiningNode> node, Blockchain blockchain)
    : m_work_id_counter(1)
    , m_rpc_client(std::make_unique<LitecoinRpcClient>(testnet))
    , m_testnet(testnet)
    , m_blockchain(blockchain)
    , m_node(node)
    , m_address_validator(blockchain, testnet ? Network::TESTNET : Network::MAINNET)
    , m_payout_manager(std::make_unique<c2pool::payout::PayoutManager>(1.0, 86400)) // 1% fee, 24h window
    , m_solo_mode(false)
    , m_solo_address("")
{
    setup_methods();
}

void MiningInterface::setup_methods()
{
    // Core mining methods - explicitly cast to MethodHandle
    Add("getwork", jsonrpccxx::MethodHandle([this](const nlohmann::json& params) -> nlohmann::json {
        return getwork();
    }));
    
    Add("submitwork", jsonrpccxx::MethodHandle([this](const nlohmann::json& params) -> nlohmann::json {
        if (params.size() < 3) {
            throw jsonrpccxx::JsonRpcException(-1, "submitwork requires 3 parameters");
        }
        return submitwork(params[0], params[1], params[2]);
    }));
    
    Add("getblocktemplate", jsonrpccxx::MethodHandle([this](const nlohmann::json& params) -> nlohmann::json {
        nlohmann::json template_params = params.empty() ? nlohmann::json::array() : params;
        return getblocktemplate(template_params);
    }));
    
    Add("submitblock", jsonrpccxx::MethodHandle([this](const nlohmann::json& params) -> nlohmann::json {
        if (params.empty()) {
            throw jsonrpccxx::JsonRpcException(-1, "submitblock requires hex data parameter");
        }
        return submitblock(params[0]);
    }));
    
    // Pool info methods
    Add("getinfo", jsonrpccxx::MethodHandle([this](const nlohmann::json& params) -> nlohmann::json {
        return getinfo();
    }));
    
    Add("getstats", jsonrpccxx::MethodHandle([this](const nlohmann::json& params) -> nlohmann::json {
        return getstats();
    }));
    
    Add("getpeerinfo", jsonrpccxx::MethodHandle([this](const nlohmann::json& params) -> nlohmann::json {
        return getpeerinfo();
    }));
    
    // Stratum methods
    Add("mining.subscribe", jsonrpccxx::MethodHandle([this](const nlohmann::json& params) -> nlohmann::json {
        std::string user_agent = params.empty() ? "" : params[0];
        return mining_subscribe(user_agent);
    }));
    
    Add("mining.authorize", jsonrpccxx::MethodHandle([this](const nlohmann::json& params) -> nlohmann::json {
        if (params.size() < 2) {
            throw jsonrpccxx::JsonRpcException(-1, "mining.authorize requires username and password");
        }
        return mining_authorize(params[0], params[1]);
    }));
    
    Add("mining.submit", jsonrpccxx::MethodHandle([this](const nlohmann::json& params) -> nlohmann::json {
        if (params.size() < 5) {
            throw jsonrpccxx::JsonRpcException(-1, "mining.submit requires 5 parameters");
        }
        return mining_submit(params[0], params[1], "", params[2], params[3], params[4]);
    }));
    
    // Enhanced payout and coinbase methods
    Add("validate_address", jsonrpccxx::MethodHandle([this](const nlohmann::json& params) -> nlohmann::json {
        if (params.empty()) {
            throw jsonrpccxx::JsonRpcException(-1, "validate_address requires address parameter");
        }
        return validate_address(params[0]);
    }));
    
    Add("build_coinbase", jsonrpccxx::MethodHandle([this](const nlohmann::json& params) -> nlohmann::json {
        if (params.empty()) {
            throw jsonrpccxx::JsonRpcException(-1, "build_coinbase requires parameters object");
        }
        return build_coinbase(params);
    }));
    
    Add("validate_coinbase", jsonrpccxx::MethodHandle([this](const nlohmann::json& params) -> nlohmann::json {
        if (params.empty()) {
            throw jsonrpccxx::JsonRpcException(-1, "validate_coinbase requires coinbase hex parameter");
        }
        return validate_coinbase(params[0]);
    }));
    
    Add("getblockcandidate", jsonrpccxx::MethodHandle([this](const nlohmann::json& params) -> nlohmann::json {
        return getblockcandidate(params);
    }));
    
    Add("getpayoutinfo", jsonrpccxx::MethodHandle([this](const nlohmann::json& params) -> nlohmann::json {
        return getpayoutinfo();
    }));
    
    Add("getminerstats", jsonrpccxx::MethodHandle([this](const nlohmann::json& params) -> nlohmann::json {
        return getminerstats();
    }));

    Add("setmessageblob", jsonrpccxx::MethodHandle([this](const nlohmann::json& params) -> nlohmann::json {
        if (params.empty()) {
            throw jsonrpccxx::JsonRpcException(-1, "setmessageblob requires hex blob parameter");
        }
        return setmessageblob(params[0]);
    }));

    Add("getmessageblob", jsonrpccxx::MethodHandle([this](const nlohmann::json& params) -> nlohmann::json {
        return getmessageblob();
    }));
}

void MiningInterface::set_operator_message_blob(const std::vector<unsigned char>& blob)
{
    std::lock_guard<std::mutex> lock(m_message_blob_mutex);
    m_operator_message_blob = blob;
}

std::vector<unsigned char> MiningInterface::get_operator_message_blob() const
{
    std::lock_guard<std::mutex> lock(m_message_blob_mutex);
    return m_operator_message_blob;
}

// ─── Live coin-daemon integration ────────────────────────────────────────────

void MiningInterface::set_coin_rpc(ltc::coin::NodeRPC* rpc, ltc::interfaces::Node* coin)
{
    m_coin_rpc  = rpc;
    m_coin_node = coin;
    LOG_INFO << "MiningInterface: coin RPC " << (rpc ? "connected" : "disconnected");
}

void MiningInterface::set_on_block_submitted(std::function<void(const std::string&, int)> fn)
{
    m_on_block_submitted = std::move(fn);
}

void MiningInterface::set_on_block_relay(std::function<void(const std::string&)> fn)
{
    m_on_block_relay = std::move(fn);
}

bool MiningInterface::has_merged_chain(uint32_t chain_id) const
{
    if (!m_mm_manager) return false;
    return m_mm_manager->get_chain_rpc(chain_id) != nullptr;
}

std::string MiningInterface::get_node_fee_hash160() const
{
    // Extract hash160 from a 25-byte P2PKH scriptPubKey (bytes 3–22)
    if (m_node_fee_script.size() != 25) return {};
    if (m_node_fee_script[0] != 0x76 || m_node_fee_script[1] != 0xa9) return {};
    static const char* HEX = "0123456789abcdef";
    std::string h160;
    h160.reserve(40);
    for (int i = 3; i < 23; ++i) {
        h160 += HEX[m_node_fee_script[i] >> 4];
        h160 += HEX[m_node_fee_script[i] & 0x0f];
    }
    return h160;
}

void MiningInterface::check_merged_mining(const std::string& block_hex,
                                          const std::string& extranonce1,
                                          const std::string& extranonce2,
                                          const JobSnapshot* job)
{
    if (!m_mm_manager) return;

    // Extract 80-byte parent header (first 160 hex chars)
    if (block_hex.size() < 160) return;
    std::string parent_header_hex = block_hex.substr(0, 160);

    // Compute parent block hash (scrypt for LTC)
    auto hdr_bytes = ParseHex(parent_header_hex);
    uint256 parent_hash;
    scrypt_1024_1_1_256(reinterpret_cast<const char*>(hdr_bytes.data()),
                        reinterpret_cast<char*>(parent_hash.data()));

    // Build stripped coinbase tx (no witness) — use per-job parts when available
    std::string coinbase_hex;
    std::vector<std::string> merkle_branches_copy;
    {
        std::lock_guard<std::mutex> lock(m_work_mutex);
        const std::string& cb1 = job ? job->coinb1 : m_cached_coinb1;
        const std::string& cb2 = job ? job->coinb2 : m_cached_coinb2;
        coinbase_hex = cb1 + extranonce1 + extranonce2 + cb2;
        merkle_branches_copy = job ? job->merkle_branches : m_cached_merkle_branches;
    }

    m_mm_manager->try_submit_merged_blocks(
        parent_header_hex,
        coinbase_hex,
        merkle_branches_copy,
        0,  // coinbase is always at index 0
        parent_hash);
}

// ─── Witness merkle root computation ──────────────────────────────────────────
// Compute the merkle root of a list of hashes (standard Bitcoin merkle tree).
static uint256 compute_witness_merkle_root(std::vector<uint256> hashes) {
    if (hashes.empty()) return uint256();
    while (hashes.size() > 1) {
        if (hashes.size() % 2 == 1)
            hashes.push_back(hashes.back());
        std::vector<uint256> next;
        next.reserve(hashes.size() / 2);
        for (size_t i = 0; i + 1 < hashes.size(); i += 2)
            next.push_back(Hash(hashes[i], hashes[i + 1]));
        hashes = std::move(next);
    }
    return hashes[0];
}

// P2Pool witness nonce: '[P2Pool]' repeated 4 times = 32 bytes
static const unsigned char P2POOL_WITNESS_NONCE_BYTES[32] = {
    0x5b, 0x50, 0x32, 0x50, 0x6f, 0x6f, 0x6c, 0x5d,
    0x5b, 0x50, 0x32, 0x50, 0x6f, 0x6f, 0x6c, 0x5d,
    0x5b, 0x50, 0x32, 0x50, 0x6f, 0x6f, 0x6c, 0x5d,
    0x5b, 0x50, 0x32, 0x50, 0x6f, 0x6f, 0x6c, 0x5d,
};

// Compute the P2Pool witness commitment hex from a raw witness merkle root.
// Returns the full script hex: "6a24aa21a9ed" + SHA256d(root || '[P2Pool]'*4)
static std::string compute_p2pool_witness_commitment_hex(const uint256& witness_root) {
    uint256 nonce;
    std::memcpy(nonce.data(), P2POOL_WITNESS_NONCE_BYTES, 32);
    uint256 commitment = Hash(witness_root, nonce);
    return "6a24aa21a9ed" + HexStr(std::span<const unsigned char>(
        reinterpret_cast<const unsigned char*>(commitment.data()), 32));
}

// ─── Merkle branch computation ────────────────────────────────────────────────
// Given the list of transaction hashes EXCLUDING the coinbase
// (i.e. from getblocktemplate tx list), compute the Stratum merkle_branches
// array that enables the miner to reconstruct the merkle root as:
//   hash = coinbase_hash
//   for b in branches: hash = Hash(hash, b)
/*static*/ std::vector<std::string>
MiningInterface::compute_merkle_branches(std::vector<std::string> tx_hashes_hex)
{
    if (tx_hashes_hex.empty()) return {};

    // Convert hex strings to uint256
    std::vector<uint256> current;
    current.reserve(tx_hashes_hex.size());
    for (const auto& h : tx_hashes_hex) {
        uint256 u;
        u.SetHex(h);
        current.push_back(u);
    }

    std::vector<std::string> branches;

    // At each tree level: the first element of `current` is the sibling of our
    // path node. Consume it as a branch, then build the next level from the rest.
    while (!current.empty()) {
        // Store in internal byte order (Stratum format: raw SHA256d output hex)
        branches.push_back(HexStr(std::span<const unsigned char>(current[0].data(), 32)));
        current.erase(current.begin());      // remove the sibling we just used
        if (current.empty()) break;

        // If the remaining list is odd, duplicate the last entry
        if (current.size() % 2 == 1)
            current.push_back(current.back());

        // Pair and hash for the next level
        std::vector<uint256> next;
        next.reserve(current.size() / 2);
        for (size_t i = 0; i + 1 < current.size(); i += 2)
            next.push_back(Hash(current[i], current[i + 1]));
        current = std::move(next);
    }

    return branches;
}

// ─── Merkle root reconstruction ──────────────────────────────────────────────
// Given a fully-assembled coinbase transaction in hex and the Stratum merkle
// branches, reconstruct the block's merkle root.
//   coinbase_hash = dSHA256(coinbase_bytes)
//   for each branch: coinbase_hash = dSHA256(coinbase_hash || branch)
/*static*/ uint256
MiningInterface::reconstruct_merkle_root(const std::string& coinbase_hex,
                                         const std::vector<std::string>& merkle_branches)
{
    auto coinbase_bytes = ParseHex(coinbase_hex);
    uint256 hash = Hash(coinbase_bytes);

    for (const auto& branch_hex : merkle_branches) {
        // Branches are in internal byte order (Stratum format)
        uint256 branch;
        auto branch_bytes = ParseHex(branch_hex);
        if (branch_bytes.size() == 32)
            memcpy(branch.begin(), branch_bytes.data(), 32);
        hash = Hash(hash, branch);
    }
    return hash;
}

// ─── Build full block from Stratum parameters ────────────────────────────────
// Assembles the block header + full transaction list from the cached template
// and the miner's Stratum submit data.
std::string
MiningInterface::build_block_from_stratum(const std::string& extranonce1,
                                          const std::string& extranonce2,
                                          const std::string& ntime,
                                          const std::string& nonce,
                                          const JobSnapshot* job) const
{
    std::lock_guard<std::mutex> lock(m_work_mutex);

    // When a JobSnapshot is provided, use its frozen template data.
    // Otherwise fall back to the live m_cached_template (legacy/solo path).
    const std::string& coinb1 = job ? job->coinb1 : m_cached_coinb1;
    const std::string& coinb2 = job ? job->coinb2 : m_cached_coinb2;

    if (coinb1.empty())
        return {};

    // Reconstruct coinbase: coinb1 + extranonce1 + extranonce2 + coinb2
    std::string coinbase_hex = coinb1 + extranonce1 + extranonce2 + coinb2;

    // Reconstruct merkle root using the job's branches (or the live cache)
    const auto& branches = job ? job->merkle_branches : m_cached_merkle_branches;
    uint256 merkle_root = reconstruct_merkle_root(coinbase_hex, branches);

    // Block header fields — from the job snapshot or the live template
    uint32_t version;
    uint256 prev_hash;
    std::string bits_hex;
    bool segwit;
    if (job) {
        version = job->version ? job->version : 536870912U;
        prev_hash.SetHex(job->gbt_prevhash.empty() ? std::string(64, '0') : job->gbt_prevhash);
        bits_hex = job->nbits.empty() ? "1d00ffff" : job->nbits;
        segwit = job->segwit_active;
    } else {
        if (!m_work_valid || m_cached_template.is_null())
            return {};
        version = m_cached_template.value("version", 536870912U);
        prev_hash.SetHex(m_cached_template.value("previousblockhash", std::string(64, '0')));
        bits_hex = m_cached_template.value("bits", std::string("1d00ffff"));
        segwit = m_segwit_active;
    }

    // ntime and nonce from miner (hex strings, 4 bytes each, BE from Stratum)
    auto ntime_bytes = ParseHex(ntime);
    auto nonce_bytes = ParseHex(nonce);
    auto bits_bytes  = ParseHex(bits_hex);

    // Stratum/GBT sends these as big-endian hex; block header needs little-endian
    std::reverse(ntime_bytes.begin(), ntime_bytes.end());
    std::reverse(nonce_bytes.begin(), nonce_bytes.end());
    std::reverse(bits_bytes.begin(),  bits_bytes.end());

    std::ostringstream block;
    // version LE
    block << std::hex << std::setfill('0')
          << std::setw(2) << ((version      ) & 0xff)
          << std::setw(2) << ((version >>  8) & 0xff)
          << std::setw(2) << ((version >> 16) & 0xff)
          << std::setw(2) << ((version >> 24) & 0xff);
    // prev_hash (already internal byte order in uint256)
    block << HexStr(std::span<const unsigned char>(prev_hash.data(), 32));
    // merkle_root
    block << HexStr(std::span<const unsigned char>(merkle_root.data(), 32));
    // ntime LE
    block << HexStr(std::span<const unsigned char>(ntime_bytes.data(), ntime_bytes.size()));
    // nbits LE
    block << HexStr(std::span<const unsigned char>(bits_bytes.data(), bits_bytes.size()));
    // nonce LE
    block << HexStr(std::span<const unsigned char>(nonce_bytes.data(), nonce_bytes.size()));

    // Transaction count (varint) + coinbase + rest of transactions
    const auto& tx_list = job ? job->tx_data : std::vector<std::string>{};
    // If no job snapshot, collect tx data from the live template
    std::vector<std::string> live_tx_data;
    if (!job && m_cached_template.contains("transactions")) {
        for (const auto& tx : m_cached_template["transactions"])
            if (tx.contains("data"))
                live_tx_data.push_back(tx["data"].get<std::string>());
    }
    const auto& txs_hex = job ? tx_list : live_tx_data;
    uint64_t tx_count = 1 + txs_hex.size(); // coinbase + template txs
    // Simple varint encoding
    if (tx_count < 0xfd)
        block << std::hex << std::setfill('0') << std::setw(2) << tx_count;
    else
        block << "fd" << std::hex << std::setfill('0')
              << std::setw(2) << (tx_count & 0xff)
              << std::setw(2) << ((tx_count >> 8) & 0xff);

    // Coinbase transaction: coinb1 + extranonce1 + extranonce2 + coinb2 is the
    // non-witness (stripped) serialization used for txid computation and the
    // Stratum merkle tree.  For segwit blocks the block body must contain the
    // witness serialization which wraps the same data with marker/flag bytes
    // and a coinbase witness stack (BIP141: 1 item of 32 bytes = P2Pool nonce).
    if (segwit) {
        // Non-witness: [version 4B][input_count 1B][inputs…][outputs…][locktime 4B]
        // Witness:     [version 4B][00 01][input_count 1B][inputs…][outputs…]
        //              [witness_stack][locktime 4B]
        block << coinbase_hex.substr(0, 8)    // version (4 bytes = 8 hex)
              << "0001"                        // segwit marker + flag
              << coinbase_hex.substr(8, coinbase_hex.size() - 16) // inputs + outputs
              << "01"                          // 1 stack item for the single coinbase input
              << "20"                          // 32 bytes
              // P2Pool witness nonce: '[P2Pool]' * 4
              << "5b5032506f6f6c5d5b5032506f6f6c5d5b5032506f6f6c5d5b5032506f6f6c5d"
              << coinbase_hex.substr(coinbase_hex.size() - 8); // locktime
    } else {
        block << coinbase_hex;
    }

    // Remaining transactions from the template
    for (const auto& tx_hex : txs_hex) {
        block << tx_hex;
    }

    // MWEB extension block (Litecoin): append HogEx flag + MWEB data
    const std::string& mweb_data = job ? job->mweb : m_cached_mweb;
    if (!mweb_data.empty())
        block << "01" << mweb_data;

    return block.str();
}

// ─── Coinbase parts construction ─────────────────────────────────────────────
// Encode an integer as a minimal CScriptNum (sign-magnitude, little-endian)
// prefixed by a 1-byte push-data length. Used for BIP34 block height.
static std::string encode_height_pushdata(int height)
{
    std::ostringstream os;
    if (height == 0) {
        os << "0100";  // PUSH1 [0x00]
        return os.str();
    }
    std::vector<uint8_t> bytes;
    uint32_t v = static_cast<uint32_t>(height);
    while (v > 0) {
        bytes.push_back(static_cast<uint8_t>(v & 0xFF));
        v >>= 8;
    }
    // If MSB is set, add a 0x00 sign byte (positive)
    if (bytes.back() & 0x80)
        bytes.push_back(0x00);

    // PUSHDATA opcode = len, then the data bytes (already little-endian)
    os << std::hex << std::setfill('0') << std::setw(2) << bytes.size();
    for (uint8_t b : bytes)
        os << std::hex << std::setfill('0') << std::setw(2) << static_cast<int>(b);
    return os.str();
}

// Encode a uint64 amount as 8 little-endian hex bytes
static std::string encode_le64(uint64_t v)
{
    std::ostringstream os;
    for (int i = 0; i < 8; ++i)
        os << std::hex << std::setfill('0') << std::setw(2)
           << static_cast<int>((v >> (i * 8)) & 0xFF);
    return os.str();
}

// Build a P2PKH output script OP_DUP OP_HASH160 <hash160> OP_EQUALVERIFY OP_CHECKSIG
// `hash160_hex` must be 40 hex chars (20 bytes).
// Returns the (length-prefixed) complete output script hex.
static std::string p2pkh_script(const std::string& hash160_hex)
{
    // 1976a914{hash160}88ac
    std::ostringstream s;
    s << "19" << "76a914" << hash160_hex << "88ac";
    return s.str();
}

/*static*/ std::pair<std::string, std::string>
MiningInterface::build_coinbase_parts(
    const nlohmann::json& tmpl,
    uint64_t coinbase_value,
    const std::vector<std::pair<std::string,uint64_t>>& outputs,
    bool raw_scripts,
    const std::vector<uint8_t>& mm_commitment,
    const std::string& witness_commitment_hex,
    const std::string& ref_hash_hex)
{
    // P2Pool-compatible coinbase split: extranonce goes into last_txout_nonce,
    // NOT into the scriptSig.  This way:
    //   - scriptSig is fixed (no miner-variable data) → share.m_coinbase is deterministic
    //   - hash_link prefix (everything before last 44 bytes) matches generate_transaction
    //   - en1+en2 fill the 8-byte last_txout_nonce in OP_RETURN (part of hash_link suffix)
    //
    // coinb1 = everything up to and including ref_hash in the OP_RETURN output
    // coinb2 = locktime only ("00000000")
    // coinbase = coinb1 + extranonce1(4B) + extranonce2(4B) + coinb2
    //
    // The en1+en2 become the P2Pool last_txout_nonce (8 bytes).
    //
    // Output ordering (must match generate_share_transaction()):
    //   1. Segwit witness commitment (if present) — value=0
    //   2. PPLNS payout outputs (sorted by amount asc, script asc) + donation last
    //   3. OP_RETURN commitment (0x6a28 + ref_hash + last_txout_nonce) — value=0

    const int height = tmpl.value("height", 1);
    const std::string height_hex = encode_height_pushdata(height);
    const int height_bytes = static_cast<int>(height_hex.size()) / 2;

    // "/c2pool/" in ASCII = 2f 63 32 70 6f 6f 6c 2f
    const std::string pool_marker = "2f633270 6f6f6c2f";
    std::string pool_marker_stripped;
    for (char c : pool_marker) { if (c != ' ') pool_marker_stripped += c; }
    const int pool_marker_bytes = static_cast<int>(pool_marker_stripped.size()) / 2;

    // AuxPoW merged mining commitment
    std::string mm_hex;
    if (!mm_commitment.empty()) {
        static const char* HEX = "0123456789abcdef";
        mm_hex.reserve(mm_commitment.size() * 2);
        for (uint8_t b : mm_commitment) {
            mm_hex += HEX[b >> 4];
            mm_hex += HEX[b & 0x0f];
        }
    }
    const int mm_bytes = static_cast<int>(mm_commitment.size());

    // ScriptSig: height + mm_commitment + pool_marker (NO extranonce!)
    const int script_total = height_bytes + mm_bytes + pool_marker_bytes;

    // Build coinb1: entire coinbase TX up to and including ref_hash in OP_RETURN
    std::ostringstream coinb1;
    coinb1 << "01000000"   // version
           << "01"         // 1 input
           << "0000000000000000000000000000000000000000000000000000000000000000"
           << "ffffffff"   // previous index
           << std::hex << std::setfill('0') << std::setw(2) << script_total
           << height_hex;

    // scriptSig: mm + pool_marker (no en1/en2 — those go into last_txout_nonce)
    if (!mm_hex.empty())
        coinb1 << mm_hex;
    coinb1 << pool_marker_stripped
           << "ffffffff";  // sequence = 0xFFFFFFFF

    // Count outputs: [segwit?] + PPLNS + OP_RETURN
    size_t num_outputs = outputs.size();
    if (!witness_commitment_hex.empty()) ++num_outputs;
    if (!ref_hash_hex.empty()) ++num_outputs;

    // Varint-encode output count
    if (num_outputs < 0xfd)
        coinb1 << std::hex << std::setfill('0') << std::setw(2) << num_outputs;
    else
        coinb1 << "fd" << std::hex << std::setfill('0')
               << std::setw(2) << (num_outputs & 0xff)
               << std::setw(2) << ((num_outputs >> 8) & 0xff);

    // Output 1: Segwit witness commitment (FIRST, matching generate_share_transaction)
    if (!witness_commitment_hex.empty()) {
        coinb1 << encode_le64(0);   // 0 satoshis
        size_t wc_len = witness_commitment_hex.size() / 2;
        coinb1 << std::hex << std::setfill('0') << std::setw(2) << wc_len;
        coinb1 << witness_commitment_hex;
    }

    // Outputs 2..N: PPLNS payouts + donation (already sorted by caller)
    for (const auto& [addr, amount] : outputs) {
        coinb1 << encode_le64(amount);
        if (raw_scripts) {
            size_t script_len = addr.size() / 2;
            coinb1 << std::hex << std::setfill('0') << std::setw(2) << script_len;
            coinb1 << addr;
        } else {
            coinb1 << p2pkh_script(addr);
        }
    }

    // Output N+1: OP_RETURN commitment (LAST, matching generate_share_transaction)
    // Script = 6a(OP_RETURN) + 28(PUSH_40) + ref_hash(32) + nonce(8)
    // Total script = 42 bytes = 0x2a
    // The nonce(8) bytes are filled by en1+en2 (between coinb1 and coinb2)
    if (!ref_hash_hex.empty()) {
        coinb1 << encode_le64(0);   // 0 satoshis
        coinb1 << "2a";             // script length = 42
        coinb1 << "6a28";           // OP_RETURN + PUSH_40
        coinb1 << ref_hash_hex;     // 32 bytes = 64 hex chars
        // nonce (8 bytes) = en1+en2 goes HERE (between coinb1 and coinb2)
    }

    // coinb2 is just locktime
    std::string coinb2 = "00000000";

    return { coinb1.str(), coinb2 };
}

std::pair<std::string, std::string>
MiningInterface::build_connection_coinbase(
    const uint256& prev_share_hash,
    const std::string& extranonce1_hex,
    const std::vector<unsigned char>& payout_script,
    const std::vector<std::pair<uint32_t, std::vector<unsigned char>>>& merged_addrs) const
{
    std::lock_guard<std::mutex> lock(m_work_mutex);
    if (!m_work_valid || m_cached_template.is_null())
        return {};

    // Build the coinbase scriptSig (FIXED — no extranonce1/2):
    //   BIP34_height + mm_commitment + pool_marker
    // This is share.m_coinbase and determines ref_hash.
    // extranonce1+extranonce2 go into last_txout_nonce (OP_RETURN), not scriptSig.
    const int height = m_cached_template.value("height", 1);
    std::string height_hex = encode_height_pushdata(height);

    // Pool marker
    const std::string pool_marker_stripped = "2f633270" "6f6f6c2f";

    // MM commitment hex
    static const char* HEX = "0123456789abcdef";
    std::string mm_hex;
    for (uint8_t b : m_cached_mm_commitment) {
        mm_hex += HEX[b >> 4];
        mm_hex += HEX[b & 0x0f];
    }

    // ScriptSig: height + mm + pool_marker (NO extranonce!)
    std::string scriptsig_hex = height_hex + mm_hex + pool_marker_stripped;

    // Decode to bytes for ref_hash computation
    std::vector<unsigned char> scriptsig_bytes;
    scriptsig_bytes.reserve(scriptsig_hex.size() / 2);
    for (size_t i = 0; i + 1 < scriptsig_hex.size(); i += 2)
        scriptsig_bytes.push_back(static_cast<unsigned char>(
            std::stoul(scriptsig_hex.substr(i, 2), nullptr, 16)));

    // Compute ref_hash via the callback (needs tracker data)
    if (!m_ref_hash_fn)
        return {};

    uint64_t subsidy = m_cached_template.value("coinbasevalue", uint64_t(0));
    uint32_t bits = 0;
    if (m_cached_template.contains("bits"))
        bits = static_cast<uint32_t>(std::stoul(
            m_cached_template["bits"].get<std::string>(), nullptr, 16));
    uint32_t timestamp = m_cached_template.value("curtime", uint32_t(0));

    // Convert cached merkle branches (hex strings) to uint256 for ref_hash callback
    std::vector<uint256> branches_u256;
    branches_u256.reserve(m_cached_merkle_branches.size());
    for (const auto& hex : m_cached_merkle_branches) {
        uint256 h;
        auto bytes = ParseHex(hex);
        if (bytes.size() == 32)
            memcpy(h.begin(), bytes.data(), 32);
        branches_u256.push_back(h);
    }

    auto [ref_hash, last_txout_nonce] = m_ref_hash_fn(
        prev_share_hash,
        scriptsig_bytes, payout_script, subsidy, bits, timestamp,
        m_segwit_active, m_cached_witness_commitment, m_cached_witness_root,
        merged_addrs, branches_u256);

    // Build ref_hash hex (32 bytes LE)
    std::string ref_hash_hex;
    {
        auto ref_chars = ref_hash.GetChars();
        for (unsigned char b : ref_chars) {
            ref_hash_hex += HEX[b >> 4];
            ref_hash_hex += HEX[b & 0x0f];
        }
    }

    // Call build_coinbase_parts with ref_hash
    // The last_txout_nonce will be filled by en1+en2 at mining time
    return build_coinbase_parts(
        m_cached_template,
        subsidy,
        m_cached_pplns_outputs,
        m_cached_raw_scripts,
        m_cached_mm_commitment,
        m_cached_witness_commitment,
        ref_hash_hex);
}

// Decode a Base58Check‐encoded address (P2PKH or P2SH) and return the
// 20-byte hash160 payload as a 40-char lowercase hex string.
// Returns "" if the address is invalid or the checksum fails.
static std::string base58check_to_hash160(const std::string& address)
{
    static constexpr const char* B58 =
        "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

    // decoded[0..24]: 1 version byte + 20 hash160 bytes + 4 checksum bytes
    uint8_t decoded[25] = {};
    for (unsigned char ch : address) {
        const char* p = std::strchr(B58, static_cast<char>(ch));
        if (!p) return "";                      // invalid Base58 character
        int carry = static_cast<int>(p - B58);
        for (int i = 24; i >= 0; --i) {
            carry += 58 * static_cast<int>(decoded[i]);
            decoded[i] = static_cast<uint8_t>(carry & 0xFF);
            carry >>= 8;
        }
        if (carry) return "";                   // value doesn't fit in 25 bytes
    }

    // Verify checksum: SHA256d(decoded[0..20])[0..4] == decoded[21..24]
    uint8_t tmp[32], chk[32];
    CSHA256().Write(decoded, 21).Finalize(tmp);
    CSHA256().Write(tmp, 32).Finalize(chk);
    for (int i = 0; i < 4; ++i)
        if (chk[i] != decoded[21 + i]) return "";  // bad checksum

    // Return bytes [1..20] as 40-char hex (skip the version byte)
    static const char* HEX = "0123456789abcdef";
    std::string hex;
    hex.reserve(40);
    for (int i = 1; i <= 20; ++i) {
        hex += HEX[decoded[i] >> 4];
        hex += HEX[decoded[i] & 0x0f];
    }
    return hex;
}

void MiningInterface::refresh_work()
{
    if (!m_coin_rpc) return;
    try {
        auto wd = m_coin_rpc->getwork();

        // Update the coin node's Variable<WorkData> so submit_block() can read it
        if (m_coin_node)
            m_coin_node->work.set(wd);

        // Collect tx hashes from WorkData
        std::vector<std::string> tx_hashes_hex;
        for (const auto& h : wd.m_hashes)
            tx_hashes_hex.push_back(h.GetHex());

        // Compute Stratum merkle branches from those hashes
        auto merkle_branches = compute_merkle_branches(tx_hashes_hex);

        // Build coinbase parts with properly split payout outputs
        uint64_t coinbase_value = wd.m_data.value("coinbasevalue", uint64_t(5000000000));
        std::pair<std::string,std::string> cb_parts;
        bool segwit_active = false;

        // Cached PPLNS data for per-connection coinbase generation
        std::vector<std::pair<std::string,uint64_t>> pplns_outputs;
        bool pplns_raw_scripts = false;
        std::string witness_commitment;
        uint256 witness_root;
        std::vector<uint8_t> mm_commitment;

        try {
            // V36 PPLNS path: use share-tracker proportional payouts directly
            if (m_pplns_fn && m_best_share_hash_fn) {
                auto best = m_best_share_hash_fn();
                if (!best.IsNull()) {
                    LOG_DEBUG_DIAG << "refresh_work: PPLNS active, best_share=" << best.GetHex().substr(0,16) << "..."
                                 << " donation_script_len=" << m_donation_script.size();
                    uint32_t nbits = std::stoul(
                        wd.m_data.value("bits", "1d00ffff"), nullptr, 16);
                    uint256 block_target = chain::bits_to_target(nbits);

                    auto expected = m_pplns_fn(best, block_target, coinbase_value, m_donation_script);

                    if (!expected.empty()) {
                        static const char* HEX = "0123456789abcdef";

                        // Convert donation script to hex for identification
                        std::string donation_script_hex;
                        for (unsigned char b : m_donation_script) {
                            donation_script_hex += HEX[b >> 4];
                            donation_script_hex += HEX[b & 0x0f];
                        }

                        // Separate PPLNS outputs from donation output
                        std::pair<std::string, uint64_t> donation_entry;
                        bool found_donation = false;

                        for (const auto& [script_bytes, amount] : expected) {
                            uint64_t sat = static_cast<uint64_t>(amount);
                            std::string hex;
                            hex.reserve(script_bytes.size() * 2);
                            for (unsigned char b : script_bytes) {
                                hex += HEX[b >> 4];
                                hex += HEX[b & 0x0f];
                            }
                            if (hex == donation_script_hex) {
                                donation_entry = {hex, sat};
                                found_donation = true;
                            } else {
                                if (sat == 0) continue; // Only skip zero-value PPLNS outputs
                                pplns_outputs.push_back({std::move(hex), sat});
                            }
                        }

                        // Sort PPLNS by (amount ascending, script ascending)
                        // matching Python's sorted(dests, key=lambda a: (amounts[a], a))[-4000:]
                        std::sort(pplns_outputs.begin(), pplns_outputs.end(),
                            [](const auto& a, const auto& b) {
                                if (a.second != b.second) return a.second < b.second;
                                return a.first < b.first;
                            });
                        constexpr size_t MAX_PPLNS = 4000;
                        if (pplns_outputs.size() > MAX_PPLNS)
                            pplns_outputs.erase(pplns_outputs.begin(),
                                                pplns_outputs.end() - MAX_PPLNS);

                        // Donation output LAST among value outputs
                        // (matches Python's generate_transaction: payouts + [donation] + OP_RETURN)
                        if (found_donation)
                            pplns_outputs.push_back(donation_entry);

                        pplns_raw_scripts = true;
                        LOG_DEBUG_DIAG << "refresh_work: V36 PPLNS coinbase with "
                                     << pplns_outputs.size() << " outputs (donation_last="
                                     << found_donation << ")";
                    }
                }
            }

            // Fallback: single output to zero-key (burn) so coinbase is always valid
            if (pplns_outputs.empty())
                pplns_outputs.push_back({"0000000000000000000000000000000000000000", coinbase_value});

            // Get merged mining commitment if an MM manager is wired
            if (m_mm_manager)
                mm_commitment = m_mm_manager->get_auxpow_commitment();

            // BIP141: compute P2Pool witness commitment from template transactions
            if (wd.m_data.contains("rules")) {
                auto rules = wd.m_data["rules"].get<std::vector<std::string>>();
                segwit_active = std::any_of(rules.begin(), rules.end(),
                    [](const auto& r) { return r == "segwit" || r == "!segwit"; });
            }
            if (segwit_active && wd.m_data.contains("transactions")) {
                // Compute raw wtxid merkle root from block template transactions
                std::vector<uint256> wtxids;
                uint256 zero;  // coinbase wtxid = 0x00
                wtxids.push_back(zero);
                for (auto& tx : wd.m_data["transactions"]) {
                    uint256 wtxid;
                    if (tx.is_object() && tx.contains("hash"))
                        wtxid.SetHex(tx["hash"].get<std::string>());
                    else if (tx.is_object() && tx.contains("txid"))
                        wtxid.SetHex(tx["txid"].get<std::string>());
                    wtxids.push_back(wtxid);
                }
                witness_root = compute_witness_merkle_root(std::move(wtxids));
                // P2Pool commitment: SHA256d(witness_root || '[P2Pool]'*4)
                witness_commitment = compute_p2pool_witness_commitment_hex(witness_root);
            }

            // Build fallback coinbase (without OP_RETURN, for non-p2pool or initial work)
            cb_parts = build_coinbase_parts(wd.m_data, coinbase_value, pplns_outputs,
                                            pplns_raw_scripts, mm_commitment, witness_commitment);
        } catch (const std::exception& e) {
            LOG_WARNING << "refresh_work: coinbase build failed: " << e.what();
            cb_parts = { "01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff", "ffffffff0100f2052a01000000434104" };
        }

        // Commit to cache under mutex
        std::lock_guard<std::mutex> lock(m_work_mutex);
        m_cached_template         = wd.m_data;
        m_cached_merkle_branches  = std::move(merkle_branches);
        m_cached_coinb1           = std::move(cb_parts.first);
        m_cached_coinb2           = std::move(cb_parts.second);
        m_segwit_active           = segwit_active;
        m_cached_pplns_outputs    = std::move(pplns_outputs);
        m_cached_raw_scripts      = pplns_raw_scripts;
        m_cached_witness_commitment = std::move(witness_commitment);
        m_cached_witness_root       = witness_root;
        m_cached_mm_commitment    = std::move(mm_commitment);
        m_cached_mweb             = wd.m_data.contains("mweb")
                                  ? wd.m_data["mweb"].get<std::string>() : "";
        m_work_valid              = true;

        LOG_INFO << "refresh_work: height=" << wd.m_data.value("height", 0)
                 << " txs=" << wd.m_hashes.size()
                 << " latency=" << wd.m_latency << "ms"
                 << " merkle_branches=" << m_cached_merkle_branches.size();

        // Push real network difficulty to external consumers (AdjustmentEngine)
        if (m_on_network_difficulty_fn) {
            try {
                uint32_t nbits_val = std::stoul(
                    wd.m_data.value("bits", "1d00ffff"), nullptr, 16);
                double net_diff = chain::target_to_difficulty(
                    chain::bits_to_target(nbits_val));
                if (net_diff > 0)
                    m_on_network_difficulty_fn(net_diff);
            } catch (...) {}
        }
    } catch (const std::exception& e) {
        LOG_WARNING << "refresh_work failed: " << e.what();
        m_work_valid = false;
    }
}

nlohmann::json MiningInterface::get_current_work_template() const
{
    std::lock_guard<std::mutex> lock(m_work_mutex);
    return m_work_valid ? m_cached_template : nlohmann::json{};
}

std::vector<std::string> MiningInterface::get_stratum_merkle_branches() const
{
    std::lock_guard<std::mutex> lock(m_work_mutex);
    return m_cached_merkle_branches;
}

std::pair<std::string, std::string> MiningInterface::get_coinbase_parts() const
{
    std::lock_guard<std::mutex> lock(m_work_mutex);
    return { m_cached_coinb1, m_cached_coinb2 };
}

bool MiningInterface::get_segwit_active() const
{
    std::lock_guard<std::mutex> lock(m_work_mutex);
    return m_segwit_active;
}

std::string MiningInterface::get_cached_mweb() const
{
    std::lock_guard<std::mutex> lock(m_work_mutex);
    return m_cached_mweb;
}

std::string MiningInterface::get_cached_witness_commitment() const
{
    std::lock_guard<std::mutex> lock(m_work_mutex);
    return m_cached_witness_commitment;
}

uint256 MiningInterface::get_cached_witness_root() const
{
    std::lock_guard<std::mutex> lock(m_work_mutex);
    return m_cached_witness_root;
}

// ─────────────────────────────────────────────────────────────────────────────

nlohmann::json MiningInterface::getwork(const std::string& request_id)
{
    LOG_DEBUG_DIAG << "getwork request received";
    
    // Get current difficulty from the c2pool node
    double current_difficulty = 1.0; // Default fallback
    std::string target_hex = "00000000ffff0000000000000000000000000000000000000000000000000000";
    
    if (m_node) {
        // Get current session difficulty and global pool difficulty
        auto difficulty_stats = m_node->get_difficulty_stats();
        if (difficulty_stats.contains("global_pool_difficulty")) {
            current_difficulty = difficulty_stats["global_pool_difficulty"];
        }
        
        // Calculate target from difficulty
        // Target = max_target / difficulty
        // max_target = 0x00000000FFFF0000000000000000000000000000000000000000000000000000
        uint256 max_target;
        max_target.SetHex("00000000FFFF0000000000000000000000000000000000000000000000000000");
        
        uint256 work_target = max_target / static_cast<uint64_t>(current_difficulty * 1000000); // Scale for precision
        target_hex = work_target.GetHex();
        
        LOG_DEBUG_DIAG << "Using pool difficulty: " << current_difficulty << ", target: " << target_hex.substr(0, 16) << "...";
    } else {
        LOG_WARNING << "No c2pool node connected, using default difficulty: " << current_difficulty;
    }
    
    // Build work data from the cached block template if available
    std::string work_data;
    {
        std::lock_guard<std::mutex> lock(m_work_mutex);
        if (m_work_valid && !m_cached_template.is_null()) {
            // Build an 80-byte header stub (version + prevhash + merkle_placeholder + time + bits + nonce_placeholder)
            uint32_t version = m_cached_template.value("version", 536870912U);
            std::string prevhash = m_cached_template.value("previousblockhash", std::string(64, '0'));
            std::string bits = m_cached_template.value("bits", std::string("1d00ffff"));
            uint32_t curtime = static_cast<uint32_t>(m_cached_template.value("curtime", uint64_t(std::time(nullptr))));

            std::ostringstream hdr;
            hdr << std::hex << std::setfill('0')
                << std::setw(2) << ((version      ) & 0xff)
                << std::setw(2) << ((version >>  8) & 0xff)
                << std::setw(2) << ((version >> 16) & 0xff)
                << std::setw(2) << ((version >> 24) & 0xff)
                << prevhash
                << std::string(64, '0') // merkle root placeholder — miners fill this in
                << std::setw(2) << ((curtime      ) & 0xff)
                << std::setw(2) << ((curtime >>  8) & 0xff)
                << std::setw(2) << ((curtime >> 16) & 0xff)
                << std::setw(2) << ((curtime >> 24) & 0xff)
                << bits
                << "00000000"; // nonce placeholder
            work_data = hdr.str();

            // Derive target from bits
            uint32_t nbits = static_cast<uint32_t>(std::stoul(bits, nullptr, 16));
            uint256 tmpl_target = chain::bits_to_target(nbits);
            target_hex = tmpl_target.GetHex();
        }
    }

    if (work_data.empty()) {
        // Fallback: static placeholder
        work_data = "00000001" + std::string(64, '0') + std::string(64, '0')
                    + "00000000" + "1d00ffff" + "00000000";
        LOG_WARNING << "getwork: no live template, returning placeholder work";
    }
    
    nlohmann::json work = {
        {"data", work_data},
        {"target", target_hex},
        {"difficulty", current_difficulty}
    };
    
    // Store work for later validation
    std::string work_id = std::to_string(m_work_id_counter++);
    m_active_work[work_id] = work;
    
    LOG_DEBUG_DIAG << "Provided work to miner, work_id=" << work_id << ", difficulty=" << current_difficulty;
    return work;
}

nlohmann::json MiningInterface::submitwork(const std::string& nonce, const std::string& header, const std::string& mix, const std::string& request_id)
{
    LOG_DEBUG_DIAG << "Work submission received - nonce: " << nonce << ", header: " << header.substr(0, 32) << "...";
    
    // Validate the submitted work by computing scrypt PoW hash
    bool work_valid = false;
    if (header.size() >= 160) { // 80 bytes = 160 hex chars
        auto header_bytes = ParseHex(header.substr(0, 160));
        if (header_bytes.size() == 80) {
            char pow_hash_bytes[32];
            scrypt_1024_1_1_256(reinterpret_cast<const char*>(header_bytes.data()), pow_hash_bytes);
            uint256 pow_hash;
            memcpy(pow_hash.begin(), pow_hash_bytes, 32);

            // Check against the template target
            uint256 target;
            {
                std::lock_guard<std::mutex> lock(m_work_mutex);
                if (m_work_valid && m_cached_template.contains("bits")) {
                    std::string bits_hex = m_cached_template["bits"].get<std::string>();
                    uint32_t bits = static_cast<uint32_t>(std::stoul(bits_hex, nullptr, 16));
                    target = chain::bits_to_target(bits);
                } else {
                    target.SetHex("00000000ffff0000000000000000000000000000000000000000000000000000");
                }
            }
            work_valid = (pow_hash <= target);
            LOG_DEBUG_DIAG << "PoW check: hash=" << pow_hash.GetHex().substr(0, 16)
                         << "... target=" << target.GetHex().substr(0, 16)
                         << "... valid=" << work_valid;
        }
    }
    
    if (work_valid && m_node) {
        // Track the mining_share submission for difficulty adjustment
        std::string session_id = "miner_" + std::to_string(m_work_id_counter);
        m_node->track_mining_share_submission(session_id, 1.0);
        
        // Create a new mining_share and add to the sharechain
        uint256 share_hash;
        share_hash.SetHex(header); // Simplified - would need proper hash calculation
        
        uint256 prev_hash = m_best_share_hash_fn ? m_best_share_hash_fn() : uint256::ZERO;
        uint256 target;
        {
            std::lock_guard<std::mutex> lock(m_work_mutex);
            if (m_work_valid && m_cached_template.contains("bits")) {
                std::string bits_hex = m_cached_template["bits"].get<std::string>();
                uint32_t bits = static_cast<uint32_t>(std::stoul(bits_hex, nullptr, 16));
                target = chain::bits_to_target(bits);
            } else {
                target.SetHex("00000000ffff0000000000000000000000000000000000000000000000000000");
            }
        }
        
        m_node->add_local_mining_share(share_hash, prev_hash, target);
        
        LOG_INFO << "Mining share submitted and added to sharechain: " << share_hash.ToString().substr(0, 16) << "...";
        LOG_INFO << "Work submission accepted";
        return true;
    } else if (work_valid) {
        LOG_INFO << "Work submission accepted (no node connected for tracking)";
        return true;
    } else {
        LOG_WARNING << "Work submission rejected - invalid work";
        return false;
    }
}

nlohmann::json MiningInterface::getblocktemplate(const nlohmann::json& params, const std::string& request_id)
{
    LOG_INFO << "getblocktemplate request received";

    // Return live template if available
    {
        std::lock_guard<std::mutex> lock(m_work_mutex);
        if (m_work_valid && !m_cached_template.empty())
            return m_cached_template;
    }

    // Fallback: static placeholder so callers always get a valid JSON object
    LOG_WARNING << "getblocktemplate: no live template yet, returning placeholder";
    return {
        {"version", 536870912},
        {"previousblockhash", "0000000000000000000000000000000000000000000000000000000000000000"},
        {"transactions", nlohmann::json::array()},
        {"coinbaseaux", nlohmann::json::object()},
        {"coinbasevalue", 5000000000LL},
        {"target", "00000000ffff0000000000000000000000000000000000000000000000000000"},
        {"mintime", 1234567890},
        {"mutable", nlohmann::json::array({"time", "transactions", "prevblock"})},
        {"noncerange", "00000000ffffffff"},
        {"sigoplimit", 20000},
        {"sizelimit", 1000000},
        {"curtime", static_cast<uint64_t>(std::time(nullptr))},
        {"bits", "1d00ffff"},
        {"height", 1},
        {"rules", nlohmann::json::array({"segwit"})}
    };
}

nlohmann::json MiningInterface::submitblock(const std::string& hex_data, const std::string& request_id)
{
    LOG_INFO << "Block submission received - size: " << hex_data.length() << " chars";

    // Block header is 80 bytes = 160 hex chars minimum
    if (hex_data.size() < 160) {
        LOG_ERROR << "submitblock: hex data too short for a valid block header";
        return {{"error", "block data too short"}};
    }

    // Parse the 80-byte block header:
    //   bytes  0- 3: version  (uint32 LE)
    //   bytes  4-35: prev_block_hash (32 bytes, internal byte order)
    //   bytes 36-67: merkle_root     (32 bytes, internal byte order)
    //   bytes 68-71: timestamp (uint32 LE)
    //   bytes 72-75: nbits     (uint32 LE)
    //   bytes 76-79: nonce     (uint32 LE)
    auto header_bytes = ParseHex(hex_data.substr(0, 160));

    // Extract prev_block_hash (bytes 4..35), reversed for display/comparison
    uint256 submitted_prev_hash;
    std::memcpy(submitted_prev_hash.data(), header_bytes.data() + 4, 32);

    // Extract merkle_root (bytes 36..67)
    uint256 submitted_merkle_root;
    std::memcpy(submitted_merkle_root.data(), header_bytes.data() + 36, 32);

    // Validate prev_block_hash matches our cached template
    {
        bool is_stale = false;
        {
            std::lock_guard<std::mutex> lock(m_work_mutex);
            if (m_work_valid && !m_cached_template.is_null()
                && m_cached_template.contains("previousblockhash"))
            {
                uint256 expected_prev;
                expected_prev.SetHex(m_cached_template["previousblockhash"].get<std::string>());
                if (submitted_prev_hash != expected_prev) {
                    LOG_WARNING << "submitblock: stale block — prev_hash mismatch"
                                << " submitted=" << submitted_prev_hash.GetHex()
                                << " expected=" << expected_prev.GetHex();
                    is_stale = true;
                }
            }

            // Reconstruct expected merkle_root from coinbase + merkle branches
            if (!is_stale && !m_cached_coinb1.empty() && !m_cached_coinb2.empty()) {
                LOG_INFO << "submitblock: merkle_root=" << submitted_merkle_root.GetHex();
            }
        }
        // Fire stale callback OUTSIDE the lock to avoid deadlock
        if (is_stale) {
            if (m_on_block_submitted && hex_data.size() >= 160) {
                m_on_block_submitted(hex_data.substr(0, 160), 253);
            }
            return {{"error", "stale block: previous block hash mismatch"}};
        }
    }

    if (m_coin_rpc) {
        try {
            bool accepted = m_coin_rpc->submit_block_hex(hex_data, "", false);
            LOG_INFO << "Block forwarded to coin daemon";
            if (accepted) {
                // Notify P2P layer with stale_info=0 (none — accepted)
                if (m_on_block_submitted && hex_data.size() >= 160) {
                    m_on_block_submitted(hex_data.substr(0, 160), 0);
                }
                // Relay full block via P2P for fast propagation
                if (m_on_block_relay) {
                    m_on_block_relay(hex_data);
                }
            }
        } catch (const std::exception& e) {
            LOG_ERROR << "submitblock failed: " << e.what();
            // Fire callback with doa stale info (254)
            if (m_on_block_submitted && hex_data.size() >= 160) {
                m_on_block_submitted(hex_data.substr(0, 160), 254);
            }
            return {{"error", std::string(e.what())}};
        }
    } else {
        LOG_WARNING << "submitblock: no coin RPC connected, block discarded";
    }

    return nullptr; // null = accepted in getblocktemplate spec
}

nlohmann::json MiningInterface::getinfo(const std::string& request_id)
{
    double current_difficulty = 1.0;
    double pool_hashrate = 0.0;
    uint64_t total_shares = 0;
    uint64_t connections = 0;
    
    // Get stats from c2pool node if available
    if (m_node) {
        auto difficulty_stats = m_node->get_difficulty_stats();
        if (difficulty_stats.contains("global_pool_difficulty")) {
            current_difficulty = difficulty_stats["global_pool_difficulty"];
        }
        
        auto hashrate_stats = m_node->get_hashrate_stats();
        if (hashrate_stats.contains("global_hashrate")) {
            pool_hashrate = hashrate_stats["global_hashrate"];
        }
        
        total_shares = m_node->get_total_mining_shares();
        connections = m_node->get_connected_peers_count();
    }
    
    // Read block height from cached template
    uint64_t block_height = 0;
    double network_hashps = 0.0;
    {
        std::lock_guard<std::mutex> lock(m_work_mutex);
        if (!m_cached_template.is_null() && m_cached_template.contains("height"))
            block_height = m_cached_template["height"].get<uint64_t>();
    }
    
    nlohmann::json protocol_messages = nlohmann::json::array();
    if (m_protocol_messages_fn) {
        try {
            protocol_messages = m_protocol_messages_fn();
        } catch (const std::exception& e) {
            LOG_WARNING << "protocol_messages hook failed: " << e.what();
        }
    }

    auto operator_blob = get_operator_message_blob();

    return {
        {"version", "c2pool/0.0.1"},
        {"protocolversion", 70015},
        {"blocks", block_height},
        {"connections", connections},
        {"difficulty", current_difficulty},
        {"networkhashps", network_hashps},
        {"poolhashps", pool_hashrate},
        {"poolshares", total_shares},
        {"generate", true},
        {"genproclimit", -1},
        {"testnet", m_testnet},
        {"paytxfee", 0.0},
        {"errors", ""},
        {"operator_message_blob_hex", to_hex(operator_blob)},
        {"protocol_messages", protocol_messages}
    };
}

nlohmann::json MiningInterface::getstats(const std::string& request_id)
{
    uint64_t total_mining_shares = 0;
    uint64_t connected_peers = 0;
    double pool_hashrate = 0.0;
    double difficulty = 1.0;
    uint64_t active_miners = 0;

    if (m_node) {
        total_mining_shares = m_node->get_total_mining_shares();
        connected_peers = m_node->get_connected_peers_count();
        auto hs = m_node->get_hashrate_stats();
        if (hs.contains("global_hashrate"))
            pool_hashrate = hs["global_hashrate"];
        auto ds = m_node->get_difficulty_stats();
        if (ds.contains("global_pool_difficulty"))
            difficulty = ds["global_pool_difficulty"];
    }

    auto* pm = m_payout_manager_ptr ? m_payout_manager_ptr : m_payout_manager.get();
    if (pm)
        active_miners = pm->get_active_miners_count();

    uint64_t block_height = 0;
    {
        std::lock_guard<std::mutex> lock(m_work_mutex);
        if (!m_cached_template.is_null() && m_cached_template.contains("height"))
            block_height = m_cached_template["height"].get<uint64_t>();
    }

    nlohmann::json stale = {{"orphan_count", 0}, {"doa_count", 0}, {"stale_count", 0}, {"stale_prop", 0.0}};
    if (m_node)
        stale = m_node->get_stale_stats();

    nlohmann::json protocol_messages = nlohmann::json::array();
    if (m_protocol_messages_fn) {
        try {
            protocol_messages = m_protocol_messages_fn();
        } catch (const std::exception& e) {
            LOG_WARNING << "protocol_messages hook failed: " << e.what();
        }
    }

    auto operator_blob = get_operator_message_blob();

    return {
        {"pool_statistics", {
            {"mining_shares", total_mining_shares},
            {"pool_hashrate", pool_hashrate},
            {"difficulty", difficulty},
            {"block_height", block_height},
            {"connected_peers", connected_peers},
            {"active_miners", active_miners},
            {"orphan_shares", stale["orphan_count"]},
            {"doa_shares", stale["doa_count"]},
            {"stale_shares", stale["stale_count"]},
            {"stale_prop", stale["stale_prop"]}
        }},
        {"operator_message_blob_hex", to_hex(operator_blob)},
        {"protocol_messages", protocol_messages}
    };
}

nlohmann::json MiningInterface::setmessageblob(const std::string& message_blob_hex,
                                               const std::string& request_id)
{
    if (message_blob_hex.empty()) {
        set_operator_message_blob({});
        return {
            {"ok", true},
            {"enabled", false},
            {"size", 0},
            {"message", "operator message blob cleared"}
        };
    }

    if (message_blob_hex.size() % 2 != 0) {
        throw jsonrpccxx::JsonRpcException(-1, "message blob hex length must be even");
    }

    std::vector<unsigned char> blob;
    try {
        blob = ParseHex(message_blob_hex);
    } catch (const std::exception& e) {
        throw jsonrpccxx::JsonRpcException(-1, std::string("invalid hex blob: ") + e.what());
    }

    if (blob.size() > 4096) {
        throw jsonrpccxx::JsonRpcException(-1, "message blob too large (max 4096 bytes)");
    }

    // Validate encrypted authority blob using V36 consensus validation path.
    auto err = ltc::validate_message_data(blob);
    if (!err.empty()) {
        throw jsonrpccxx::JsonRpcException(-1, "message blob rejected: " + err);
    }

    set_operator_message_blob(blob);
    return {
        {"ok", true},
        {"enabled", true},
        {"size", blob.size()},
        {"hex", message_blob_hex}
    };
}

nlohmann::json MiningInterface::getmessageblob(const std::string& request_id)
{
    auto blob = get_operator_message_blob();
    return {
        {"enabled", !blob.empty()},
        {"size", blob.size()},
        {"hex", to_hex(blob)}
    };
}

nlohmann::json MiningInterface::getpeerinfo(const std::string& request_id)
{
    nlohmann::json peers = nlohmann::json::array();
    if (m_node) {
        size_t count = m_node->get_connected_peers_count();
        // Return minimal info — detailed peer data requires NodeImpl access
        peers.push_back({
            {"connected_peers", count}
        });
    }
    return peers;
}

nlohmann::json MiningInterface::getpayoutinfo(const std::string& request_id)
{
    auto* pm = m_payout_manager_ptr ? m_payout_manager_ptr : m_payout_manager.get();
    if (!pm)
        return {{"error", "payout manager not available"}};

    return pm->get_payout_statistics();
}

nlohmann::json MiningInterface::getminerstats(const std::string& request_id)
{
    nlohmann::json result;
    auto* pm = m_payout_manager_ptr ? m_payout_manager_ptr : m_payout_manager.get();
    if (pm) {
        result["active_miners"] = pm->get_active_miners_count();
        result["pplns_active"] = pm->has_pplns_data();
        result["payout_statistics"] = pm->get_payout_statistics();
    }
    if (m_node) {
        result["hashrate"] = m_node->get_hashrate_stats();
        result["difficulty"] = m_node->get_difficulty_stats();
        result["stale_stats"] = m_node->get_stale_stats();
    }
    return result;
}

// ──────────────────────── p2pool-compatible REST endpoints ────────────────────

nlohmann::json MiningInterface::rest_local_rate()
{
    double rate = 0.0;
    if (m_node) {
        auto hs = m_node->get_hashrate_stats();
        if (hs.contains("global_hashrate"))
            rate = hs["global_hashrate"];
    }
    return rate;
}

nlohmann::json MiningInterface::rest_global_rate()
{
    double rate = 0.0;
    {
        std::lock_guard<std::mutex> lock(m_work_mutex);
        if (!m_cached_template.is_null() && m_cached_template.contains("networkhashps"))
            rate = m_cached_template["networkhashps"].get<double>();
    }
    return rate;
}

nlohmann::json MiningInterface::rest_current_payouts()
{
    nlohmann::json result = nlohmann::json::object();
    auto* pm = m_payout_manager_ptr ? m_payout_manager_ptr : m_payout_manager.get();
    if (pm && pm->has_pplns_data()) {
        uint64_t subsidy = 0;
        {
            std::lock_guard<std::mutex> lock(m_work_mutex);
            if (!m_cached_template.is_null())
                subsidy = m_cached_template.value("coinbasevalue", uint64_t(0));
        }
        if (subsidy > 0) {
            auto outputs = pm->calculate_pplns_outputs(subsidy);
            static const char* HEX = "0123456789abcdef";
            for (const auto& [script, amount] : outputs) {
                std::string key;
                key.reserve(script.size() * 2);
                for (unsigned char b : script) {
                    key += HEX[b >> 4];
                    key += HEX[b & 0x0f];
                }
                result[key] = amount;
            }
        }
    }
    return result;
}

nlohmann::json MiningInterface::rest_users()
{
    auto* pm = m_payout_manager_ptr ? m_payout_manager_ptr : m_payout_manager.get();
    return pm ? nlohmann::json(pm->get_active_miners_count()) : nlohmann::json(0);
}

nlohmann::json MiningInterface::rest_fee()
{
    return m_pool_fee_percent;
}

nlohmann::json MiningInterface::rest_recent_blocks()
{
    nlohmann::json arr = nlohmann::json::array();
    std::lock_guard<std::mutex> lock(m_blocks_mutex);
    for (const auto& b : m_found_blocks)
        arr.push_back({{"height", b.height}, {"hash", b.hash}, {"ts", b.ts}});
    return arr;
}

nlohmann::json MiningInterface::rest_uptime()
{
    // Return daemon uptime in seconds
    static auto start_time = std::chrono::steady_clock::now();
    auto now = std::chrono::steady_clock::now();
    auto uptime_seconds = std::chrono::duration_cast<std::chrono::seconds>(now - start_time).count();
    return nlohmann::json(uptime_seconds);
}

nlohmann::json MiningInterface::rest_config() const
{
    if (m_runtime_config)
        return m_runtime_config->to_json();
    return nlohmann::json::object();
}

nlohmann::json MiningInterface::rest_connected_miners()
{
    // Return count of connected miners and active sessions
    nlohmann::json result = nlohmann::json::object();
    auto* pm = m_payout_manager_ptr ? m_payout_manager_ptr : m_payout_manager.get();
    
    result["total_connected"] = pm ? pm->get_active_miners_count() : 0;
    result["active_workers"] = pm ? pm->get_active_miners_count() : 0;
    result["stale_count"] = 0;  // Will be populated by actual stratum session tracking
    
    return result;
}

nlohmann::json MiningInterface::rest_stratum_stats()
{
    // Return stratum protocol statistics
    nlohmann::json result = nlohmann::json::object();
    
    // Mining share metrics
    result["difficulty"] = 1.0;
    result["accepted_shares"] = 0;
    result["rejected_shares"] = 0;
    result["stale_shares"] = 0;
    result["hashrate"] = 0.0;
    
    // Worker diversity
    result["active_workers"] = 0;
    result["unique_addresses"] = 0;
    
    // Recent submissions
    result["shares_per_minute"] = 0.0;
    result["last_share_time"] = static_cast<uint64_t>(std::time(nullptr));

    {
        std::lock_guard<std::mutex> lock(m_control_mutex);
        result["mining_enabled"] = m_mining_enabled;
        result["banned_count"] = static_cast<uint64_t>(m_banned_targets.size());
    }
    
    return result;
}

nlohmann::json MiningInterface::rest_global_stats()
{
    // Return comprehensive node statistics
    nlohmann::json result = nlohmann::json::object();
    
    // Pool stats
    result["pool_hashrate"] = 0.0;
    result["network_hashrate"] = 0.0;
    result["pool_stale_ratio"] = 0.0;
    
    // Share chain
    result["shares_in_chain"] = 0;
    result["unique_miners"] = 0;
    result["current_height"] = 0;
    
    // Uptime and health
    result["uptime_seconds"] = rest_uptime();
    result["status"] = "operational";
    result["last_block"] = 0;
    
    return result;
}

nlohmann::json MiningInterface::rest_sharechain_stats()
{
    // Delegate to the live tracker callback if wired
    if (m_sharechain_stats_fn)
        return m_sharechain_stats_fn();

    // Fallback: return empty stub when no tracker is connected
    nlohmann::json result = nlohmann::json::object();
    result["total_shares"] = 0;
    result["shares_by_version"] = nlohmann::json::object();
    result["shares_by_miner"] = nlohmann::json::object();
    result["chain_height"] = 0;
    result["chain_tip_hash"] = "";
    result["fork_count"] = 0;
    result["heaviest_fork_weight"] = 0.0;
    result["average_difficulty"] = 1.0;
    result["difficulty_trend"] = nlohmann::json::array();
    auto now = std::time(nullptr);
    nlohmann::json timeline = nlohmann::json::array();
    for (int i = 5; i >= 0; --i) {
        nlohmann::json slot;
        slot["timestamp"] = now - (i * 600);
        slot["share_count"] = 0;
        slot["miner_distribution"] = nlohmann::json::object();
        timeline.push_back(slot);
    }
    result["timeline"] = timeline;
    return result;
}

nlohmann::json MiningInterface::rest_sharechain_window()
{
    if (m_sharechain_window_fn)
        return m_sharechain_window_fn();

    // Fallback stub
    nlohmann::json result;
    result["shares"] = nlohmann::json::array();
    result["total"] = 0;
    result["best_hash"] = "";
    result["chain_length"] = 0;
    return result;
}

nlohmann::json MiningInterface::rest_control_mining_start()
{
    std::lock_guard<std::mutex> lock(m_control_mutex);
    m_mining_enabled = true;
    return nlohmann::json::object({
        {"ok", true},
        {"action", "start"},
        {"mining_enabled", m_mining_enabled}
    });
}

nlohmann::json MiningInterface::rest_control_mining_stop()
{
    std::lock_guard<std::mutex> lock(m_control_mutex);
    m_mining_enabled = false;
    return nlohmann::json::object({
        {"ok", true},
        {"action", "stop"},
        {"mining_enabled", m_mining_enabled}
    });
}

nlohmann::json MiningInterface::rest_control_mining_restart()
{
    std::lock_guard<std::mutex> lock(m_control_mutex);
    m_mining_enabled = true;
    return nlohmann::json::object({
        {"ok", true},
        {"action", "restart"},
        {"mining_enabled", m_mining_enabled}
    });
}

nlohmann::json MiningInterface::rest_control_mining_ban(const std::string& target)
{
    std::lock_guard<std::mutex> lock(m_control_mutex);
    if (!target.empty()) {
        m_banned_targets.insert(target);
    }
    return nlohmann::json::object({
        {"ok", !target.empty()},
        {"action", "ban"},
        {"target", target},
        {"banned_count", static_cast<uint64_t>(m_banned_targets.size())}
    });
}

nlohmann::json MiningInterface::rest_control_mining_unban(const std::string& target)
{
    std::lock_guard<std::mutex> lock(m_control_mutex);
    if (!target.empty()) {
        m_banned_targets.erase(target);
    }
    return nlohmann::json::object({
        {"ok", !target.empty()},
        {"action", "unban"},
        {"target", target},
        {"banned_count", static_cast<uint64_t>(m_banned_targets.size())}
    });
}

void MiningInterface::record_found_block(uint64_t height, const uint256& hash, uint64_t ts)
{
    if (ts == 0) ts = static_cast<uint64_t>(std::time(nullptr));
    std::lock_guard<std::mutex> lock(m_blocks_mutex);
    m_found_blocks.insert(m_found_blocks.begin(), FoundBlock{height, hash.GetHex(), ts});
    if (m_found_blocks.size() > 100)
        m_found_blocks.resize(100);
}

// ── Log endpoints (read directly from debug.log) ───────────────────────

static std::string tail_file(const std::filesystem::path& path, size_t max_lines)
{
    std::ifstream f(path, std::ios::ate);
    if (!f.is_open()) return {};

    const auto size = f.tellg();
    if (size <= 0) return {};

    // Scan backwards for newlines
    std::string result;
    size_t lines = 0;
    std::streamoff pos = size;
    while (pos > 0 && lines <= max_lines) {
        --pos;
        f.seekg(pos);
        char c;
        f.get(c);
        if (c == '\n' && pos + 1 < size)
            ++lines;
    }
    if (pos > 0) {
        // skip the newline we're on
        f.seekg(pos + 1);
    } else {
        f.seekg(0);
    }
    result.resize(static_cast<size_t>(size - f.tellg()));
    f.read(result.data(), static_cast<std::streamsize>(result.size()));
    return result;
}

std::string MiningInterface::rest_web_log()
{
    auto path = core::filesystem::config_path() / "debug.log";
    return tail_file(path, 500);
}

std::string MiningInterface::rest_logs_export(const std::string& scope,
                                               int64_t /*from_ts*/, int64_t /*to_ts*/,
                                               const std::string& format)
{
    // Read all lines, optionally filter by scope keyword
    auto path = core::filesystem::config_path() / "debug.log";
    std::ifstream f(path);
    if (!f.is_open()) return "# log file not found\n";

    std::string out;
    std::string line;
    while (std::getline(f, line)) {
        // Scope filter: if scope is "node","stratum","security" etc, check if keyword appears
        if (!scope.empty() && scope != "all") {
            std::string upper_scope = scope;
            for (auto& c : upper_scope) c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
            if (line.find(upper_scope) == std::string::npos &&
                line.find(scope) == std::string::npos)
                continue;
        }
        if (format == "csv") {
            out += "0," + scope + "," + line + '\n';
        } else if (format == "jsonl") {
            nlohmann::json j;
            j["ts"] = 0;
            j["scope"] = scope;
            j["line"] = line;
            out += j.dump() + '\n';
        } else {
            out += line + '\n';
        }
    }
    return out;
}

void MiningInterface::set_pool_fee_percent(double fee_percent)
{
    m_pool_fee_percent = fee_percent;
}

// Try to build a scriptPubKey from either a Base58Check or Bech32 address.
// Returns empty vector on failure.
static std::vector<unsigned char> address_to_script(const std::string& address)
{
    // Try Bech32 first (tltc1..., ltc1..., bc1..., tb1...)
    static const std::vector<std::string> bech32_hrps = {
        "tltc", "ltc", "bc", "tb"
    };
    for (const auto& hrp : bech32_hrps) {
        std::string prefix = hrp + "1";
        if (address.size() > prefix.size() &&
            address.substr(0, prefix.size()) == prefix)
        {
            int witver = -1;
            std::vector<uint8_t> prog;
            if (bech32::decode_segwit(hrp, address, witver, prog)) {
                // P2WPKH: OP_0 0x14 <20 bytes>   P2WSH: OP_0 0x20 <32 bytes>
                std::vector<unsigned char> script;
                script.push_back(static_cast<unsigned char>(witver == 0 ? 0x00 : (0x50 + witver)));
                script.push_back(static_cast<unsigned char>(prog.size()));
                script.insert(script.end(), prog.begin(), prog.end());
                return script;
            }
            break; // matched prefix but decode failed
        }
    }

    // Try Base58Check (P2PKH)
    auto h160 = base58check_to_hash160(address);
    if (h160.size() == 40) {
        std::vector<unsigned char> script = {0x76, 0xa9, 0x14};
        for (size_t i = 0; i < h160.size(); i += 2)
            script.push_back(static_cast<unsigned char>(
                std::stoul(h160.substr(i, 2), nullptr, 16)));
        script.push_back(0x88);
        script.push_back(0xac);
        return script;
    }

    return {}; // unrecognised format
}

void MiningInterface::set_node_fee_from_address(double percent, const std::string& address)
{
    auto script = address_to_script(address);
    if (script.empty()) {
        LOG_WARNING << "set_node_fee_from_address: invalid address " << address;
        return;
    }
    set_node_fee(percent, script);
    m_node_fee_address = address;
}

void MiningInterface::set_donation_script_from_address(const std::string& address)
{
    auto script = address_to_script(address);
    if (script.empty()) return;
    set_donation_script(script);
}

nlohmann::json MiningInterface::mining_subscribe(const std::string& user_agent, const std::string& request_id)
{
    LOG_INFO << "Stratum mining.subscribe from: " << user_agent;
    
    // Return stratum subscription response
    return nlohmann::json::array({
        nlohmann::json::array({"mining.notify", "subscription_id_1"}),
        "extranonce1",
        0 // extranonce2_size = 0 (p2pool per-connection coinbase)
    });
}

nlohmann::json MiningInterface::mining_authorize(const std::string& username, const std::string& password, const std::string& request_id)
{
    LOG_INFO << "Stratum mining.authorize for user: " << username;
    
    // Validate the username as a payout address for the configured blockchain/network
    if (!is_valid_address(username)) {
        std::string blockchain_name = m_address_validator.get_blockchain_name(m_blockchain);
        LOG_WARNING << "Authorization failed: Invalid address for " 
                   << blockchain_name << " " 
                   << (m_testnet ? "testnet" : "mainnet") << ": " << username;
        
        nlohmann::json error_response;
        error_response["result"] = false;
        error_response["error"] = {
            {"code", -1},
            {"message", "Invalid payout address for " + blockchain_name + 
                       " " + (m_testnet ? "testnet" : "mainnet")}
        };
        return error_response;
    }
    
    LOG_INFO << "Authorization successful for address: " << username;
    return true;
}

nlohmann::json MiningInterface::mining_submit(const std::string& username, const std::string& job_id, const std::string& extranonce1, const std::string& extranonce2, const std::string& ntime, const std::string& nonce, const std::string& request_id,
    const std::map<uint32_t, std::vector<unsigned char>>& merged_addresses,
    const JobSnapshot* job)
{
    LOG_DEBUG_DIAG << "Stratum mining.submit from " << username << " for job " << job_id
                   << " - nonce: " << nonce << ", extranonce2: " << extranonce2 << ", ntime: " << ntime;
    
    // Basic share validation
    bool share_valid = true;
    
    // Validate hex parameters
    if (extranonce2.empty() || ntime.empty() || nonce.empty()) {
        LOG_WARNING << "Invalid share parameters from " << username;
        return false;
    }
    
    // Validate nonce format (should be 8 hex chars)
    if (nonce.length() != 8) {
        LOG_WARNING << "Invalid nonce length from " << username << ": " << nonce;
        return false;
    }
    
    // Validate extranonce2 format
    if (extranonce2.length() != 8) {
        LOG_WARNING << "Invalid extranonce2 length from " << username << ": " << extranonce2;
        return false;
    }
    
    // Validate timestamp format (should be 8 hex chars)
    if (ntime.length() != 8) {
        LOG_WARNING << "Invalid ntime length from " << username << ": " << ntime;
        return false;
    }
    
    // Calculate share difficulty
    double share_difficulty = calculate_share_difficulty(job_id, extranonce1, extranonce2, ntime, nonce);
    
    if (m_solo_mode) {
        // Solo mining mode - work directly with blockchain
        LOG_DEBUG_DIAG << "Solo mining share from " << username << " (difficulty: " << share_difficulty << ")";
        
        // In solo mode, check if share meets network difficulty for block submission
        std::string payout_address = m_solo_address.empty() ? username : m_solo_address;
        
        // Calculate payout allocation if we have a payout manager
        if (m_payout_manager_ptr) {
            // Simulate block reward for calculation (25 LTC = 2500000000 satoshis)
            uint64_t block_reward = 2500000000; // 25 LTC in satoshis
            auto allocation = m_payout_manager_ptr->calculate_payout(block_reward);
            
            if (allocation.is_valid()) {
                LOG_DEBUG_DIAG << "Solo mining payout allocation:";
                LOG_DEBUG_DIAG << "  Miner (" << payout_address << "): " << allocation.miner_percent << "% = " << allocation.miner_amount << " satoshis";
                LOG_DEBUG_DIAG << "  Developer: " << allocation.developer_percent << "% = " << allocation.developer_amount << " satoshis (" << allocation.developer_address << ")";
                if (allocation.node_owner_amount > 0) {
                    LOG_DEBUG_DIAG << "  Node owner: " << allocation.node_owner_percent << "% = " << allocation.node_owner_amount << " satoshis (" << allocation.node_owner_address << ")";
                }
                
                // Allocation is already baked into coinbase parts by refresh_work() →
                // build_coinbase_parts(). When a valid block is found below, it carries
                // the correct developer and node-owner fee outputs.
            }
        }
        
        LOG_DEBUG_DIAG << "Solo mining share accepted - primary payout address: " << payout_address;
        
        // Check if share meets network difficulty and attempt block submission
        if (m_coin_rpc && !extranonce1.empty()) {
            std::string block_hex = build_block_from_stratum(extranonce1, extranonce2, ntime, nonce, job);
            if (!block_hex.empty()) {
                // Check merged mining targets for every share (aux targets are lower)
                check_merged_mining(block_hex, extranonce1, extranonce2, job);

                // Check PoW hash against the blockchain target before submitting
                auto block_bytes = ParseHex(block_hex.substr(0, 160));
                if (block_bytes.size() == 80) {
                    char pow_hash_bytes[32];
                    scrypt_1024_1_1_256(reinterpret_cast<const char*>(block_bytes.data()), pow_hash_bytes);
                    uint256 pow_hash;
                    memcpy(pow_hash.begin(), pow_hash_bytes, 32);

                    uint256 block_target;
                    {
                        std::lock_guard<std::mutex> lock(m_work_mutex);
                        if (!m_cached_template.is_null() && m_cached_template.contains("bits")) {
                            std::string bits_hex = m_cached_template["bits"].get<std::string>();
                            uint32_t bits = static_cast<uint32_t>(std::stoul(bits_hex, nullptr, 16));
                            block_target = chain::bits_to_target(bits);
                        }
                    }

                    if (!block_target.IsNull() && pow_hash <= block_target) {
                        // Validate merkle root before submitting
                        uint256 header_merkle;
                        std::memcpy(header_merkle.data(), block_bytes.data() + 36, 32);

                        std::string coinbase_hex;
                        uint256 expected_merkle;
                        {
                            const std::string& cb1 = job ? job->coinb1 : m_cached_coinb1;
                            const std::string& cb2 = job ? job->coinb2 : m_cached_coinb2;
                            const auto& branches = job ? job->merkle_branches : m_cached_merkle_branches;
                            coinbase_hex = cb1 + extranonce1 + extranonce2 + cb2;
                            expected_merkle = reconstruct_merkle_root(coinbase_hex, branches);
                        }

                        if (header_merkle != expected_merkle) {
                            LOG_ERROR << "Block merkle_root mismatch!"
                                      << " header=" << header_merkle.GetHex()
                                      << " expected=" << expected_merkle.GetHex();
                        } else {
                            LOG_INFO << "Block meets blockchain target! Submitting to coin daemon";
                            submitblock(block_hex);
                        }
                    }
                }
            }
        }
        
        return nlohmann::json{{"result", true}};
    } else {
        // Standard pool mode - track shares for sharechain and payouts

        // Extract primary address from multiaddress username format.
        // Format: PRIMARY_ADDR[,MERGED_ADDR...][.WORKER_NAME]
        std::string primary_addr = username;
        {
            auto dot_pos = primary_addr.rfind('.');
            if (dot_pos != std::string::npos && dot_pos > 20)
                primary_addr = primary_addr.substr(0, dot_pos);
            auto comma_pos = primary_addr.find(',');
            if (comma_pos != std::string::npos)
                primary_addr = primary_addr.substr(0, comma_pos);
        }
        std::string share_address = base58check_to_hash160(primary_addr);
        if (share_address.size() != 40) {
            // Case 4 (Python work.py): invalid/empty LTC address but miner provided an
            // explicit DOGE merged address → derive LTC hash160 from DOGE P2PKH script.
            // LTC and DOGE use identical secp256k1 keys: same pubkey_hash, different version byte.
            static constexpr uint32_t DOGE_CHAIN_ID = 98;
            auto doge_it = merged_addresses.find(DOGE_CHAIN_ID);
            if (doge_it != merged_addresses.end()) {
                const auto& doge_script = doge_it->second;
                // P2PKH script: 76 a9 14 <20-byte hash160> 88 ac
                if (doge_script.size() == 25 &&
                    doge_script[0] == 0x76 && doge_script[1] == 0xa9 && doge_script[2] == 0x14) {
                    static const char* HEX = "0123456789abcdef";
                    std::string h160;
                    h160.reserve(40);
                    for (int i = 3; i < 23; ++i) {
                        h160 += HEX[doge_script[i] >> 4];
                        h160 += HEX[doge_script[i] & 0x0f];
                    }
                    share_address = h160;
                    LOG_DEBUG_DIAG << "mining_submit: Case 4 — LTC share hash160 derived from DOGE merged address";
                }
            }
        }
        if (share_address.size() != 40) {
            // Case 3 (Python work.py): no valid LTC or DOGE address → redistribute
            // according to the node's configured --redistribute mode.
            if (m_address_fallback_fn) {
                share_address = m_address_fallback_fn(primary_addr);
                if (share_address.size() == 40)
                    LOG_DEBUG_DIAG << "mining_submit: Case 3 — redistributed share for invalid address '"
                                 << primary_addr << "'";
            }
            if (share_address.size() != 40)
                LOG_WARNING << "mining_submit: cannot resolve share address for '"
                            << primary_addr << "' — share will carry zero-hash payout";
        }

        // V36 probabilistic node fee: with probability m_node_fee_percent%,
        // replace the miner's address with the node operator's address.
        // This means ~fee% of shares carry the operator's address in PPLNS.
        if (m_node_fee_percent > 0.0 && !m_node_fee_script.empty()) {
            float roll = core::random::random_float(0.0f, 100.0f);
            if (roll < static_cast<float>(m_node_fee_percent)) {
                // Replace with node operator address for this share
                // The script is stored as raw bytes; for share tracking we pass
                // the hex representation of the hash160 (bytes 3..22 of P2PKH script)
                if (m_node_fee_script.size() == 25) { // P2PKH: 76 a9 14 <20 bytes> 88 ac
                    static const char* HEX = "0123456789abcdef";
                    std::string h160;
                    h160.reserve(40);
                    for (int i = 3; i < 23; ++i) {
                        h160 += HEX[m_node_fee_script[i] >> 4];
                        h160 += HEX[m_node_fee_script[i] & 0x0f];
                    }
                    share_address = h160;
                    LOG_DEBUG_POOL << "Node fee: share " << job_id
                                   << " address replaced → operator (roll="
                                   << roll << " < " << m_node_fee_percent << ")";
                }
            }
        }
        
        // Track mining_share submission for statistics
        if (m_node) {
            m_node->track_mining_share_submission(username, share_difficulty);
        }

        // Record share contribution for payout calculation (pool mode only)
        if (m_payout_manager) {
            m_payout_manager->record_share_contribution(share_address, share_difficulty);
            LOG_DEBUG_POOL << "Share contribution recorded: " << share_address << " (difficulty: " << share_difficulty << ")";
        }

        // Create a proper V36 share in the tracker with all block template data.
        // The payout_script is built from share_address (which may have been
        // probabilistically replaced with the node operator's address for the
        // primary chain node fee).  Merged addresses are passed through
        // unmodified — Python p2pool does NOT apply node fee to merged chains.
        if (m_create_share_fn) {
            ShareCreationParams params;

            // Build P2PKH script from share_address (40-char hex hash160)
            if (share_address.size() == 40) {
                params.payout_script = {0x76, 0xa9, 0x14};
                for (size_t i = 0; i < share_address.size(); i += 2)
                    params.payout_script.push_back(static_cast<unsigned char>(
                        std::stoul(share_address.substr(i, 2), nullptr, 16)));
                params.payout_script.push_back(0x88);
                params.payout_script.push_back(0xac);
            }

            params.merged_addresses = merged_addresses;
            params.nonce = static_cast<uint32_t>(std::stoul(nonce, nullptr, 16));
            params.timestamp = static_cast<uint32_t>(std::stoul(ntime, nullptr, 16));

            // Extract block template fields — prefer job snapshot over live template
            {
                std::lock_guard<std::mutex> lock(m_work_mutex);
                if (job) {
                    params.block_version = job->version;
                    params.prev_block_hash.SetHex(job->gbt_prevhash);
                    params.bits = static_cast<uint32_t>(std::stoul(job->nbits, nullptr, 16));
                    params.subsidy = job->subsidy;
                } else if (m_work_valid) {
                    params.block_version = m_cached_template.value("version", 536870912U);
                    if (m_cached_template.contains("previousblockhash")) {
                        params.prev_block_hash.SetHex(
                            m_cached_template["previousblockhash"].get<std::string>());
                    }
                    if (m_cached_template.contains("bits")) {
                        params.bits = static_cast<uint32_t>(std::stoul(
                            m_cached_template["bits"].get<std::string>(), nullptr, 16));
                    }
                    params.subsidy = m_cached_template.value("coinbasevalue", uint64_t(0));
                }

                // Build the actual mined coinbase: coinb1 + en1 + en2 + coinb2
                // In the new split, en1+en2 fill the last_txout_nonce (in OP_RETURN),
                // not the scriptSig.  So the scriptSig is the same in all coinbases.
                std::string full_coinbase_hex;
                {
                    const std::string& cb1 = job ? job->coinb1 : m_cached_coinb1;
                    const std::string& cb2 = job ? job->coinb2 : m_cached_coinb2;
                    full_coinbase_hex = cb1 + extranonce1 + extranonce2 + cb2;
                }

                // Extract scriptSig from the coinbase (scriptSig is fixed, no en1/en2).
                // Layout: version(4) + vin_count(1) + prev_hash(32) + prev_idx(4) + script_len(1+)
                auto cb_bytes = ParseHex(full_coinbase_hex);
                if (cb_bytes.size() > 41) {
                    size_t pos = 41;
                    uint64_t scriptsig_len = cb_bytes[pos++];
                    if (scriptsig_len < 0xfd && pos + scriptsig_len <= cb_bytes.size()) {
                        params.coinbase_scriptSig.assign(
                            cb_bytes.begin() + pos,
                            cb_bytes.begin() + pos + scriptsig_len);
                    }
                }

                // Convert string merkle branches to uint256 (internal byte order)
                const auto& branches = job ? job->merkle_branches : m_cached_merkle_branches;
                params.merkle_branches.reserve(branches.size());
                for (const auto& branch_hex : branches) {
                    uint256 h;
                    auto branch_bytes = ParseHex(branch_hex);
                    if (branch_bytes.size() == 32)
                        memcpy(h.begin(), branch_bytes.data(), 32);
                    params.merkle_branches.push_back(h);
                }

                // Segwit fields for SegwitData on the share
                params.segwit_active = job ? job->segwit_active : m_segwit_active;
                if (params.segwit_active) {
                    if (job && !job->witness_commitment_hex.empty()) {
                        params.witness_commitment_hex = job->witness_commitment_hex;
                        params.witness_root = job->witness_root;
                    } else {
                        // Fallback: use cached values from refresh_work
                        params.witness_commitment_hex = m_cached_witness_commitment;
                        params.witness_root = m_cached_witness_root;
                    }
                }

                // Pass the actual mined coinbase TX bytes for hash_link computation.
                if (!full_coinbase_hex.empty())
                    params.full_coinbase_bytes = ParseHex(full_coinbase_hex);

                // Optional operator-provided authority message blob (V36 message_data).
                params.message_data = get_operator_message_blob();

                // Use the share chain tip from work-generation time (stored in job)
                // so ref_hash matches the one embedded in the coinbase OP_RETURN.
                if (job)
                    params.prev_share_hash = job->prev_share_hash;
            }

            if (!params.payout_script.empty() && params.bits != 0) {
                m_create_share_fn(params);
            }
        }
        
        // Attempt block construction + submission only when PoW meets blockchain target.
        if (m_coin_rpc && !extranonce1.empty()) {
            std::string block_hex = build_block_from_stratum(extranonce1, extranonce2, ntime, nonce, job);
            if (!block_hex.empty()) {
                // Check merged mining targets for every share (aux targets are lower)
                check_merged_mining(block_hex, extranonce1, extranonce2, job);

                auto block_bytes = ParseHex(block_hex.substr(0, 160));
                if (block_bytes.size() == 80) {
                    char pow_hash_bytes[32];
                    scrypt_1024_1_1_256(reinterpret_cast<const char*>(block_bytes.data()), pow_hash_bytes);
                    uint256 pow_hash;
                    memcpy(pow_hash.begin(), pow_hash_bytes, 32);

                    uint256 block_target;
                    {
                        std::lock_guard<std::mutex> lock(m_work_mutex);
                        if (!m_cached_template.is_null() && m_cached_template.contains("bits")) {
                            std::string bits_hex = m_cached_template["bits"].get<std::string>();
                            uint32_t bits = static_cast<uint32_t>(std::stoul(bits_hex, nullptr, 16));
                            block_target = chain::bits_to_target(bits);
                        }
                    }

                    if (!block_target.IsNull() && pow_hash <= block_target) {
                        uint256 header_merkle;
                        std::memcpy(header_merkle.data(), block_bytes.data() + 36, 32);

                        std::string coinbase_hex;
                        uint256 expected_merkle;
                        {
                            const std::string& cb1 = job ? job->coinb1 : m_cached_coinb1;
                            const std::string& cb2 = job ? job->coinb2 : m_cached_coinb2;
                            const auto& branches = job ? job->merkle_branches : m_cached_merkle_branches;
                            coinbase_hex = cb1 + extranonce1 + extranonce2 + cb2;
                            expected_merkle = reconstruct_merkle_root(coinbase_hex, branches);
                        }

                        if (header_merkle != expected_merkle) {
                            LOG_ERROR << "Pool block merkle_root mismatch!"
                                      << " header=" << header_merkle.GetHex()
                                      << " expected=" << expected_merkle.GetHex();
                        } else {
                            LOG_INFO << "Pool block merkle_root validated, submitting to coin daemon";
                            submitblock(block_hex);
                        }
                    }
                }
            }
        }
        
        return nlohmann::json{{"result", true}};
    }
}

nlohmann::json MiningInterface::validate_address(const std::string& address)
{
    LOG_DEBUG_DIAG << "Address validation request for: " << address;
    
    nlohmann::json result = nlohmann::json::object();
    
    try {
        if (m_payout_manager) {
            // Use the existing address validator from payout manager
            auto validation_result = m_payout_manager->get_address_validator()->validate_address(address);
            
            result["valid"] = validation_result.is_valid;
            result["address"] = address;
            result["type"] = static_cast<int>(validation_result.type);
            result["blockchain"] = static_cast<int>(validation_result.blockchain);
            result["network"] = static_cast<int>(validation_result.network);
            
            if (!validation_result.is_valid) {
                result["error"] = validation_result.error_message;
            }
            
            LOG_DEBUG_DIAG << "Address validation result: " << (validation_result.is_valid ? "VALID" : "INVALID");
            
        } else {
            result["valid"] = false;
            result["error"] = "Payout manager not available";
        }
        
    } catch (const std::exception& e) {
        LOG_ERROR << "Address validation error: " << e.what();
        result["valid"] = false;
        result["error"] = std::string("Validation failed: ") + e.what();
    }
    
    return result;
}

nlohmann::json MiningInterface::build_coinbase(const nlohmann::json& params)
{
    LOG_INFO << "Coinbase construction request received";
    
    try {
        if (!m_payout_manager) {
            throw std::runtime_error("Payout manager not available");
        }
        
        // Extract parameters
        uint64_t block_reward = params.value("block_reward", 2500000000ULL); // Default 25 LTC
        std::string miner_address = params.value("miner_address", "");
        double dev_fee_percent = params.value("dev_fee_percent", 0.0);
        double node_fee_percent = params.value("node_fee_percent", 0.0);
        
        if (miner_address.empty()) {
            throw std::runtime_error("Miner address is required");
        }
        
        // Validate the miner address first
        auto addr_validation = m_payout_manager->get_address_validator()->validate_address(miner_address);
        if (!addr_validation.is_valid) {
            throw std::runtime_error("Invalid miner address: " + addr_validation.error_message);
        }
        
        // Build detailed coinbase
        auto result = m_payout_manager->build_coinbase_detailed(block_reward, miner_address, 
                                                               dev_fee_percent, node_fee_percent);
        
        LOG_INFO << "Coinbase construction successful for " << miner_address;
        return result;
        
    } catch (const std::exception& e) {
        LOG_ERROR << "Coinbase construction error: " << e.what();
        return nlohmann::json{
            {"error", std::string("Coinbase construction failed: ") + e.what()}
        };
    }
}

nlohmann::json MiningInterface::validate_coinbase(const std::string& coinbase_hex)
{
    LOG_DEBUG_DIAG << "Coinbase validation request - hex length: " << coinbase_hex.length();
    
    nlohmann::json result = nlohmann::json::object();
    
    try {
        if (!m_payout_manager) {
            throw std::runtime_error("Payout manager not available");
        }
        
        bool is_valid = m_payout_manager->validate_coinbase_transaction(coinbase_hex);
        
        result["valid"] = is_valid;
        result["coinbase_hex"] = coinbase_hex;
        result["hex_length"] = coinbase_hex.length();
        result["byte_length"] = coinbase_hex.length() / 2;
        
        if (!is_valid) {
            result["error"] = "Coinbase transaction validation failed";
        }
        
        LOG_DEBUG_DIAG << "Coinbase validation result: " << (is_valid ? "VALID" : "INVALID");
        
    } catch (const std::exception& e) {
        LOG_ERROR << "Coinbase validation error: " << e.what();
        result["valid"] = false;
        result["error"] = std::string("Validation failed: ") + e.what();
    }
    
    return result;
}

nlohmann::json MiningInterface::getblockcandidate(const nlohmann::json& params)
{
    LOG_DEBUG_DIAG << "Block candidate request received";
    
    try {
        // Get base block template (this would normally come from the coin node)
        auto base_template = getblocktemplate(nlohmann::json::array());
        
        // Enhance with coinbase construction if payout manager available
        if (m_payout_manager && params.contains("miner_address")) {
            std::string miner_address = params["miner_address"];
            uint64_t coinbase_value = base_template.value("coinbasevalue", 2500000000ULL);
            
            // Build coinbase with payout distribution
            auto coinbase_result = m_payout_manager->build_coinbase_detailed(coinbase_value, miner_address);
            
            // Add coinbase info to block template
            base_template["coinbase_outputs"] = coinbase_result["outputs"];
            base_template["coinbase_hex"] = coinbase_result["coinbase_hex"];
            base_template["payout_distribution"] = true;
            
            LOG_DEBUG_DIAG << "Block candidate with payout distribution generated";
        } else {
            base_template["payout_distribution"] = false;
            LOG_DEBUG_DIAG << "Basic block candidate generated (no payout distribution)";
        }
        
        // Add validation info
        base_template["candidate_valid"] = true;
        base_template["generation_time"] = static_cast<uint64_t>(std::time(nullptr));
        
        return base_template;
        
    } catch (const std::exception& e) {
        LOG_ERROR << "Block candidate generation error: " << e.what();
        return nlohmann::json{
            {"error", std::string("Block candidate generation failed: ") + e.what()},
            {"candidate_valid", false}
        };
    }
}

/// WebServer Implementation
WebServer::WebServer(net::io_context& ioc, const std::string& address, uint16_t port, bool testnet)
    : ioc_(ioc)
    , acceptor_(ioc)
    , bind_address_(address)
    , port_(port)
    , stratum_port_(port + 10)  // Default stratum port is +10 from main port
    , running_(false)
    , testnet_(testnet)
    , blockchain_(Blockchain::LITECOIN)
    , solo_mode_(false)
{
    mining_interface_ = std::make_shared<MiningInterface>(testnet);
}

WebServer::WebServer(net::io_context& ioc, const std::string& address, uint16_t port, bool testnet, std::shared_ptr<IMiningNode> node)
    : ioc_(ioc)
    , acceptor_(ioc)
    , bind_address_(address)
    , port_(port)
    , stratum_port_(port + 10)
    , running_(false)
    , testnet_(testnet)
    , blockchain_(Blockchain::LITECOIN)
    , solo_mode_(false)
{
    mining_interface_ = std::make_shared<MiningInterface>(testnet, node);
}

WebServer::WebServer(net::io_context& ioc, const std::string& address, uint16_t port, bool testnet, std::shared_ptr<IMiningNode> node, Blockchain blockchain)
    : ioc_(ioc)
    , acceptor_(ioc)
    , bind_address_(address)
    , port_(port)
    , stratum_port_(port + 10)
    , running_(false)
    , testnet_(testnet)
    , blockchain_(blockchain)
    , solo_mode_(false)
{
    mining_interface_ = std::make_shared<MiningInterface>(testnet, node, blockchain);
}

WebServer::~WebServer()
{
    stop();
}

bool WebServer::start()
{
    try {
        // Bind and listen on the HTTP port
        auto const address = net::ip::make_address(bind_address_);
        tcp::endpoint endpoint{address, port_};
        
        acceptor_.open(endpoint.protocol());
        acceptor_.set_option(net::socket_base::reuse_address(true));
        acceptor_.bind(endpoint);
        acceptor_.listen(net::socket_base::max_listen_connections);
        
        LOG_INFO << "WebServer started on " << bind_address_ << ":" << port_;
        
        // Start accepting HTTP connections
        accept_connections();
        
        // Start stratum server if configured
        if (stratum_port_ > 0) {
            start_stratum_server();
        }

        // If a coin RPC is connected, schedule a recurring work-refresh timer
        if (m_coin_rpc_) {
            auto timer = std::make_shared<net::steady_timer>(ioc_);
            // Use a shared_ptr<function> so the lambda can reschedule itself
            auto fn = std::make_shared<std::function<void(beast::error_code)>>();
            *fn = [this, timer, fn](beast::error_code ec) {
                if (ec || !running_) return;
                try { mining_interface_->refresh_work(); }
                catch (const std::exception& e) { LOG_WARNING << "refresh_work failed: " << e.what(); }
                catch (...) { LOG_WARNING << "refresh_work failed: unknown error"; }
                timer->expires_after(std::chrono::seconds(5));
                timer->async_wait(*fn);
            };
            // First poll after a short delay to let the io_context settle
            timer->expires_after(std::chrono::milliseconds(500));
            timer->async_wait(*fn);
            LOG_INFO << "Work-refresh timer scheduled (every 5 s)";
        }
        
        running_ = true;
        return true;
        
    } catch (const std::exception& e) {
        LOG_ERROR << "Failed to start WebServer: " << e.what();
        return false;
    }
}

void WebServer::set_on_block_submitted(std::function<void(const std::string&, int)> fn)
{
    mining_interface_->set_on_block_submitted(std::move(fn));
}

void WebServer::set_on_block_relay(std::function<void(const std::string&)> fn)
{
    mining_interface_->set_on_block_relay(std::move(fn));
}

void WebServer::trigger_work_refresh()
{
    mining_interface_->refresh_work();
}

void WebServer::set_coin_rpc(ltc::coin::NodeRPC* rpc, ltc::interfaces::Node* coin)
{
    m_coin_rpc_  = rpc;
    m_coin_node_ = coin;
    mining_interface_->set_coin_rpc(rpc, coin);
    LOG_INFO << "WebServer: coin RPC " << (rpc ? "attached" : "detached");
}

void WebServer::set_best_share_hash_fn(std::function<uint256()> fn)
{
    mining_interface_->set_best_share_hash_fn(std::move(fn));
}

void WebServer::set_pplns_fn(MiningInterface::pplns_fn_t fn)
{
    mining_interface_->set_pplns_fn(std::move(fn));
}

void WebServer::set_merged_mining_manager(c2pool::merged::MergedMiningManager* mgr)
{
    mining_interface_->set_merged_mining_manager(mgr);
}

bool WebServer::start_solo()
{
    solo_mode_ = true;
    
    try {
        // In solo mode, only start stratum server
        if (stratum_port_ > 0) {
            start_stratum_server();
            LOG_INFO << "WebServer started in solo mode on Stratum port " << stratum_port_;
            running_ = true;
            return true;
        } else {
            LOG_ERROR << "Solo mode requires Stratum port configuration";
            return false;
        }
        
    } catch (const std::exception& e) {
        LOG_ERROR << "Failed to start WebServer in solo mode: " << e.what();
        return false;
    }
}

void WebServer::stop()
{
    if (running_) {
        try {
            acceptor_.close();
            stop_stratum_server();
            running_ = false;
            LOG_INFO << "WebServer stopped";
        } catch (const std::exception& e) {
            LOG_ERROR << "Error stopping WebServer: " << e.what();
        }
    }
}

bool WebServer::start_stratum_server()
{
    try {
        if (!stratum_server_) {
            stratum_server_ = std::make_unique<StratumServer>(ioc_, bind_address_, stratum_port_, mining_interface_);
        }
        
        bool started = stratum_server_->start();
        if (started) {
            LOG_INFO << "Stratum server started on port " << stratum_port_;
        }
        return started;
        
    } catch (const std::exception& e) {
        LOG_ERROR << "Failed to start Stratum server: " << e.what();
        return false;
    }
}

void WebServer::stop_stratum_server()
{
    if (stratum_server_) {
        stratum_server_->stop();
        stratum_server_.reset();
        LOG_INFO << "Stratum server stopped";
    }
}

void WebServer::set_stratum_port(uint16_t port)
{
    stratum_port_ = port;
}

void WebServer::accept_connections()
{
    acceptor_.async_accept(
        [this](beast::error_code ec, tcp::socket socket)
        {
            handle_accept(ec, std::move(socket));
        });
}

void WebServer::handle_accept(beast::error_code ec, tcp::socket socket)
{

    if (!ec) {
        // Create and run HTTP session
        std::make_shared<HttpSession>(std::move(socket), mining_interface_)->run();
    } else {
        LOG_ERROR << "HTTP accept error: " << ec.message();
    }
    
    // Continue accepting new connections
    if (running_) {
        accept_connections();
    }
}

bool WebServer::is_stratum_running() const
{
    return stratum_server_ && stratum_server_->is_running();
}

uint16_t WebServer::get_stratum_port() const
{
    return stratum_port_;
}

/// LitecoinRpcClient Implementation
LitecoinRpcClient::LitecoinRpcClient(bool testnet)
    : testnet_(testnet)
{
}

LitecoinRpcClient::SyncStatus LitecoinRpcClient::get_sync_status()
{
    SyncStatus status;
    status.is_synced = true;  // Assume synced for now
    status.progress = 1.0;
    status.current_blocks = 3945867;  // Mock value for testing
    status.total_headers = 3945867;
    status.initial_block_download = false;
    status.error_message = "";
    
    return status;
}

bool LitecoinRpcClient::is_connected()
{
    return true;  // Assume connected for now
}

std::string LitecoinRpcClient::execute_cli_command(const std::string& command)
{
    return "OK";  // Mock response for testing
}

/// StratumServer Implementation
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
        // Create and start Stratum session
        std::make_shared<StratumSession>(std::move(socket), mining_interface_)->start();
    } else {
        LOG_ERROR << "Stratum accept error: " << ec.message();
    }
    
    // Continue accepting new connections
    if (running_) {
        accept_connections();
    }
}

/// StratumSession Implementation
StratumSession::StratumSession(tcp::socket socket, std::shared_ptr<MiningInterface> mining_interface)
    : socket_(std::move(socket))
    , mining_interface_(mining_interface)
{
    subscription_id_ = generate_subscription_id();
    extranonce1_ = generate_extranonce1();
    hashrate_tracker_.set_difficulty_bounds(0.001, 65536.0);
    hashrate_tracker_.set_target_time_per_mining_share(10.0);  // 10 sec/pseudoshare like Python p2pool
    hashrate_tracker_.enable_vardiff();  // Only per-connection trackers should auto-adjust
}

void StratumSession::start()
{
    LOG_INFO << "StratumSession started for client: " << socket_.remote_endpoint();
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
        
        LOG_INFO << "Stratum message received: " << line;
        
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
        } else if (method == "mining.set_merged_addresses") {
            response = handle_set_merged_addresses(params, id);
        } else {
            // Unknown method
            send_error(-1, "Unknown method", id);
            return;
        }
        
        send_response(response);

        // After subscribe response is sent, follow up with difficulty + work
        if (method == "mining.subscribe") {
            send_set_difficulty(hashrate_tracker_.get_current_difficulty());
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

        // Strip worker name suffix (e.g., ".r1c")
        auto dot_pos = username_.rfind('.');
        if (dot_pos != std::string::npos && dot_pos > 20)
            username_ = username_.substr(0, dot_pos);

        // Parse merged addresses — two supported formats:
        //   Slash format: PRIMARY/CHAIN_ID:ADDR/CHAIN_ID:ADDR
        //   Comma format: PRIMARY,MERGED_ADDR  (chain_id from MM manager)
        auto slash_pos = username_.find('/');
        auto comma_pos = username_.find(',');
        if (slash_pos != std::string::npos) {
            std::string remainder = username_.substr(slash_pos + 1);
            username_ = username_.substr(0, slash_pos);
            std::istringstream ss(remainder);
            std::string token;
            while (std::getline(ss, token, '/')) {
                auto colon = token.find(':');
                if (colon != std::string::npos && colon > 0 && colon + 1 < token.size()) {
                    try {
                        uint32_t chain_id = static_cast<uint32_t>(std::stoul(token.substr(0, colon)));
                        merged_addresses_[chain_id] = token.substr(colon + 1);
                    } catch (...) {
                        // skip malformed entries
                    }
                }
            }
        } else if (comma_pos != std::string::npos) {
            // Comma-separated: "LTC_ADDR,DOGE_ADDR[,ADDR2...]"
            // First address is primary; subsequent are merged chains.
            // Use chain_id=0 as placeholder (MM manager resolves actual chain).
            std::string merged_part = username_.substr(comma_pos + 1);
            username_ = username_.substr(0, comma_pos);
            // For single merged chain (common case: LTC+DOGE), assign chain_id=0
            if (!merged_part.empty()) {
                merged_addresses_[0] = merged_part;
            }
        }
        if (!merged_addresses_.empty())
            LOG_INFO << "Merged addresses from username: " << merged_addresses_.size() << " chain(s)";
        
        LOG_INFO << "Mining authorization successful for: " << username_;

        // Case 2 (Python work.py): if LTC address is valid but no explicit DOGE merged
        // address provided, auto-derive DOGE merged address from the same hash160.
        // LTC and DOGE use identical secp256k1 keys → same pubkey_hash, different version byte.
        // We store the LTC address under DOGE_CHAIN_ID; base58check_to_hash160() is
        // version-byte-agnostic, so the script produced will be hash160-identical.
        static constexpr uint32_t DOGE_CHAIN_ID = 98;
        if (mining_interface_ && mining_interface_->has_merged_chain(DOGE_CHAIN_ID)) {
            if (merged_addresses_.find(DOGE_CHAIN_ID) == merged_addresses_.end()) {
                auto h160 = base58check_to_hash160(username_);
                if (h160.size() == 40) {
                    merged_addresses_[DOGE_CHAIN_ID] = username_;
                    LOG_INFO << "Case 2: auto-generated DOGE merged address from LTC address for " << username_;
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
    
    // Stale detection: check if job_id is still active
    auto job_it = active_jobs_.find(job_id);
    if (job_it == active_jobs_.end()) {
        ++stale_shares_;
        LOG_INFO << "Stale share from " << username_ << " for expired job " << job_id;
        nlohmann::json response;
        response["id"] = request_id;
        response["result"] = false;
        response["error"] = nlohmann::json::array({21, "Stale share", nullptr});
        return response;
    }
    
    // Calculate share difficulty using per-connection coinbase and job-specific template data
    const auto& job = job_it->second;
    double share_difficulty = MiningInterface::calculate_share_difficulty(
        job.coinb1, job.coinb2,
        extranonce1_, extranonce2, ntime, nonce,
        job.version, job.gbt_prevhash, job.nbits, job.merkle_branches);
    double required_difficulty = hashrate_tracker_.get_current_difficulty();

    // Record ALL submissions for vardiff timing (accepted + rejected), like Python p2pool.
    // This lets vardiff discover the miner's actual hashrate even when shares are below target.
    double old_difficulty = required_difficulty;
    hashrate_tracker_.record_mining_share_submission(share_difficulty, share_difficulty >= required_difficulty);

    double new_difficulty = hashrate_tracker_.get_current_difficulty();
    if (new_difficulty != old_difficulty) {
        send_set_difficulty(new_difficulty);
        LOG_DEBUG_DIAG << "VARDIFF adjustment for " << username_ << ": "
                       << old_difficulty << " -> " << new_difficulty;
    }

    if (share_difficulty < required_difficulty) {
        ++rejected_shares_;
        nlohmann::json response;
        response["id"] = request_id;
        response["result"] = false;
        response["error"] = nlohmann::json::array({23, "Low difficulty share", nullptr});
        return response;
    }

    // Valid share
    ++accepted_shares_;
    
    // Forward the accepted share to MiningInterface for block-level checking.
    // Convert per-chain merged addresses (Base58Check strings) to scriptPubKeys.
    std::map<uint32_t, std::vector<unsigned char>> merged_scripts;
    for (const auto& [chain_id, addr] : merged_addresses_) {
        auto h160 = base58check_to_hash160(addr);
        if (h160.size() == 40) {
            std::vector<unsigned char> script = {0x76, 0xa9, 0x14};
            for (size_t i = 0; i < h160.size(); i += 2)
                script.push_back(static_cast<unsigned char>(
                    std::stoul(h160.substr(i, 2), nullptr, 16)));
            script.push_back(0x88);
            script.push_back(0xac);
            merged_scripts[chain_id] = std::move(script);
        }
    }

    // Build a JobSnapshot from the frozen JobEntry data
    MiningInterface::JobSnapshot snapshot;
    snapshot.coinb1          = job.coinb1;
    snapshot.coinb2          = job.coinb2;
    snapshot.gbt_prevhash    = job.gbt_prevhash;
    snapshot.nbits           = job.nbits;
    snapshot.version         = job.version;
    snapshot.merkle_branches = job.merkle_branches;
    snapshot.tx_data         = job.tx_data;
    snapshot.mweb            = job.mweb;
    snapshot.segwit_active   = job.segwit_active;
    snapshot.prev_share_hash = job.prev_share_hash;
    snapshot.subsidy         = job.subsidy;
    snapshot.witness_commitment_hex = job.witness_commitment_hex;
    snapshot.witness_root            = job.witness_root;

    mining_interface_->mining_submit(username_, job_id, extranonce1_, extranonce2, ntime, nonce, "", merged_scripts,
        &snapshot);
    
    LOG_DEBUG_DIAG << "Share accepted from " << username_ << " (diff=" << share_difficulty
                   << ", accepted=" << accepted_shares_ << ", stale=" << stale_shares_
                   << ", rejected=" << rejected_shares_ << ")";
    
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
        LOG_ERROR << "Error sending Stratum response: " << e.what();
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
    nlohmann::json notification;
    notification["id"] = nullptr;
    notification["method"] = "mining.set_difficulty";
    notification["params"] = nlohmann::json::array({difficulty});
    
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
        LOG_WARNING << "send_notify_work: no live template yet, retrying in 1s";
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

    // Populate from live block template
    {
        gbt_prevhash = tmpl.value("previousblockhash", "");
        prevhash = gbt_to_stratum_prevhash(gbt_prevhash);

        version_u32 = static_cast<uint32_t>(tmpl.value("version", 0x20000000));
        std::ostringstream ss;
        ss << std::hex << std::setw(8) << std::setfill('0')
           << version_u32;
        version = ss.str();

        if (tmpl.contains("bits"))
            nbits = tmpl["bits"].get<std::string>();
        else
            nbits = "1d00ffff";

        if (tmpl.contains("curtime"))
            curtime = static_cast<uint32_t>(tmpl["curtime"].get<uint64_t>());

        LOG_DEBUG_DIAG << "send_notify_work: live template height="
                       << tmpl.value("height", 0) << " prevhash=" << prevhash.substr(0, 16) << "...";
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
    uint256 frozen_prev_share;
    if (auto fn = mining_interface_->get_best_share_hash_fn())
        frozen_prev_share = fn();
    {
        // Build P2PKH payout script from username (authorized address)
        std::vector<unsigned char> payout_script;
        if (!username_.empty()) {
            auto h160 = base58check_to_hash160(username_);
            if (h160.size() == 40) {
                payout_script = {0x76, 0xa9, 0x14};
                for (size_t i = 0; i < h160.size(); i += 2)
                    payout_script.push_back(static_cast<unsigned char>(
                        std::stoul(h160.substr(i, 2), nullptr, 16)));
                payout_script.push_back(0x88);
                payout_script.push_back(0xac);
            }
        }

        // Build merged address entries
        std::vector<std::pair<uint32_t, std::vector<unsigned char>>> merged_addrs;
        for (const auto& [chain_id, addr] : merged_addresses_) {
            auto h160 = base58check_to_hash160(addr);
            if (h160.size() == 40) {
                std::vector<unsigned char> script = {0x76, 0xa9, 0x14};
                for (size_t i = 0; i < h160.size(); i += 2)
                    script.push_back(static_cast<unsigned char>(
                        std::stoul(h160.substr(i, 2), nullptr, 16)));
                script.push_back(0x88);
                script.push_back(0xac);
                merged_addrs.push_back({chain_id, std::move(script)});
            }
        }

        auto [cb1, cb2] = mining_interface_->build_connection_coinbase(
            frozen_prev_share, extranonce1_, payout_script, merged_addrs);
        if (!cb1.empty()) {
            coinb1 = std::move(cb1);
            coinb2 = std::move(cb2);
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
    active_jobs_[job_id] = {prevhash, gbt_prevhash, nbits, curtime, coinb1, coinb2,
                            version_u32, merkle_branches_vec, {}, "", false, {}, 0, ""};

    // Store the SAME frozen prev_share_hash that was used for ref_hash computation
    active_jobs_[job_id].prev_share_hash = frozen_prev_share;

    // Populate tx_data, mweb, segwit_active, subsidy, witness_commitment from snapshot
    {
        auto& je = active_jobs_[job_id];
        je.segwit_active = mining_interface_->get_segwit_active();
        je.mweb = mining_interface_->get_cached_mweb();

        // Freeze subsidy and witness commitment at job creation time
        auto cur_tmpl = mining_interface_->get_current_work_template();
        if (!cur_tmpl.empty() && !cur_tmpl.is_null()) {
            je.subsidy = cur_tmpl.value("coinbasevalue", uint64_t(0));
        }
        // Use the P2Pool witness commitment and root computed in refresh_work()
        je.witness_commitment_hex = mining_interface_->get_cached_witness_commitment();
        je.witness_root = mining_interface_->get_cached_witness_root();

        if (!tmpl.empty() && !tmpl.is_null() && tmpl.contains("transactions")) {
            for (const auto& tx : tmpl["transactions"]) {
                if (tx.contains("data"))
                    je.tx_data.push_back(tx["data"].get<std::string>());
            }
        }
    }

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
        work_push_timer_->expires_after(std::chrono::seconds(4));
        work_push_timer_->async_wait(*fn);
    };
    work_push_timer_->expires_after(std::chrono::seconds(4));
    work_push_timer_->async_wait(*fn);
}

std::string StratumSession::generate_extranonce1()
{
    static std::atomic<uint32_t> extranonce_counter{0};
    uint32_t value = extranonce_counter.fetch_add(1);
    std::stringstream ss;
    ss << std::hex << std::setw(8) << std::setfill('0') << value;
    return ss.str();
}

bool MiningInterface::is_valid_address(const std::string& address) const
{
    if (m_payout_manager) {
        auto validator = m_payout_manager->get_address_validator();
        if (validator) {
            auto result = validator->validate_address(address);
            return result.is_valid;
        }
    }
    
    // Basic validation - check length and format
    if (address.length() < 26 || address.length() > 62) {
        return false;
    }
    
    // Check for valid characters (alphanumeric + some special chars)
    for (char c : address) {
        if (!std::isalnum(c) && c != '1' && c != '2' && c != '3') {
            return false;
        }
    }
    
    return true;
}

double MiningInterface::calculate_share_difficulty(const std::string& job_id, const std::string& extranonce1,
                                                   const std::string& extranonce2,
                                                   const std::string& ntime, const std::string& nonce) const
{
    // Build the 80-byte block header, compute scrypt hash, and derive difficulty.
    std::lock_guard<std::mutex> lock(m_work_mutex);

    if (!m_work_valid || m_cached_template.is_null() || m_cached_coinb1.empty())
        return 0.0;

    // Reconstruct coinbase: coinb1 + extranonce1 + extranonce2 + coinb2
    std::string coinbase_hex = m_cached_coinb1 + extranonce1 + extranonce2 + m_cached_coinb2;
    uint256 merkle_root = reconstruct_merkle_root(coinbase_hex, m_cached_merkle_branches);

    // Build 80-byte header (little-endian fields)
    uint32_t version = m_cached_template.value("version", 536870912U);
    uint256 prev_hash;
    prev_hash.SetHex(m_cached_template.value("previousblockhash", std::string(64, '0')));

    std::vector<unsigned char> header;
    header.reserve(80);

    // version (4 bytes LE)
    header.push_back(static_cast<unsigned char>((version      ) & 0xff));
    header.push_back(static_cast<unsigned char>((version >>  8) & 0xff));
    header.push_back(static_cast<unsigned char>((version >> 16) & 0xff));
    header.push_back(static_cast<unsigned char>((version >> 24) & 0xff));

    // prev_hash (32 bytes, internal byte order)
    header.insert(header.end(), prev_hash.data(), prev_hash.data() + 32);

    // merkle_root (32 bytes)
    header.insert(header.end(), merkle_root.data(), merkle_root.data() + 32);

    // ntime (4 bytes LE — miner sends BE hex, reverse for header)
    auto ntime_bytes = ParseHex(ntime);
    std::reverse(ntime_bytes.begin(), ntime_bytes.end());
    header.insert(header.end(), ntime_bytes.begin(), ntime_bytes.end());

    // nbits (4 bytes LE — GBT gives BE hex, reverse for header)
    std::string bits_hex = m_cached_template.value("bits", std::string("1d00ffff"));
    auto bits_bytes = ParseHex(bits_hex);
    std::reverse(bits_bytes.begin(), bits_bytes.end());
    header.insert(header.end(), bits_bytes.begin(), bits_bytes.end());

    // nonce (4 bytes LE — miner sends BE hex, reverse for header)
    auto nonce_bytes = ParseHex(nonce);
    std::reverse(nonce_bytes.begin(), nonce_bytes.end());
    header.insert(header.end(), nonce_bytes.begin(), nonce_bytes.end());

    if (header.size() != 80)
        return 0.0;

    // Compute scrypt hash
    char pow_hash_bytes[32];
    scrypt_1024_1_1_256(reinterpret_cast<const char*>(header.data()), pow_hash_bytes);

    uint256 pow_hash;
    memcpy(pow_hash.begin(), pow_hash_bytes, 32);

    // difficulty = truediffone / pow_hash_as_double
    // truediffone = 0x00000000FFFF0000... (Litecoin difficulty-1 target)
    // For a 256-bit hash, difficulty = 2^224 / pow_hash (approximate)
    static const double truediffone = 26959535291011309493156476344723991336010898738574164086137773096960.0; // 0xFFFF * 2^208
    if (pow_hash.IsNull())
        return 0.0;

    // Convert pow_hash to a double (most significant bytes)
    double hash_val = 0.0;
    for (int i = 31; i >= 0; --i)
        hash_val = hash_val * 256.0 + static_cast<double>(pow_hash.data()[i]);

    if (hash_val == 0.0)
        return 0.0;

    return truediffone / hash_val;
}

double MiningInterface::calculate_share_difficulty(const std::string& coinb1, const std::string& coinb2,
                                                   const std::string& extranonce1, const std::string& extranonce2,
                                                   const std::string& ntime, const std::string& nonce) const
{
    std::lock_guard<std::mutex> lock(m_work_mutex);

    if (!m_work_valid || m_cached_template.is_null())
        return 0.0;

    // Reconstruct coinbase from per-connection parts
    std::string coinbase_hex = coinb1 + extranonce1 + extranonce2 + coinb2;
    uint256 merkle_root = reconstruct_merkle_root(coinbase_hex, m_cached_merkle_branches);

    uint32_t version = m_cached_template.value("version", 536870912U);
    uint256 prev_hash;
    prev_hash.SetHex(m_cached_template.value("previousblockhash", std::string(64, '0')));

    std::vector<unsigned char> header;
    header.reserve(80);

    header.push_back(static_cast<unsigned char>((version      ) & 0xff));
    header.push_back(static_cast<unsigned char>((version >>  8) & 0xff));
    header.push_back(static_cast<unsigned char>((version >> 16) & 0xff));
    header.push_back(static_cast<unsigned char>((version >> 24) & 0xff));

    header.insert(header.end(), prev_hash.data(), prev_hash.data() + 32);
    header.insert(header.end(), merkle_root.data(), merkle_root.data() + 32);

    // ntime, nbits, nonce: miner/GBT sends as BE hex, header needs LE bytes
    auto ntime_bytes = ParseHex(ntime);
    std::reverse(ntime_bytes.begin(), ntime_bytes.end());
    header.insert(header.end(), ntime_bytes.begin(), ntime_bytes.end());

    std::string bits_hex = m_cached_template.value("bits", std::string("1d00ffff"));
    auto bits_bytes = ParseHex(bits_hex);
    std::reverse(bits_bytes.begin(), bits_bytes.end());
    header.insert(header.end(), bits_bytes.begin(), bits_bytes.end());

    auto nonce_bytes = ParseHex(nonce);
    std::reverse(nonce_bytes.begin(), nonce_bytes.end());
    header.insert(header.end(), nonce_bytes.begin(), nonce_bytes.end());

    if (header.size() != 80)
        return 0.0;

    char pow_hash_bytes[32];
    scrypt_1024_1_1_256(reinterpret_cast<const char*>(header.data()), pow_hash_bytes);

    uint256 pow_hash;
    memcpy(pow_hash.begin(), pow_hash_bytes, 32);

    static const double truediffone = 26959535291011309493156476344723991336010898738574164086137773096960.0;
    if (pow_hash.IsNull())
        return 0.0;

    double hash_val = 0.0;
    for (int i = 31; i >= 0; --i)
        hash_val = hash_val * 256.0 + static_cast<double>(pow_hash.data()[i]);

    if (hash_val == 0.0)
        return 0.0;

    return truediffone / hash_val;
}

/*static*/
double MiningInterface::calculate_share_difficulty(
    const std::string& coinb1, const std::string& coinb2,
    const std::string& extranonce1, const std::string& extranonce2,
    const std::string& ntime, const std::string& nonce,
    uint32_t version, const std::string& prevhash_hex,
    const std::string& nbits_hex,
    const std::vector<std::string>& merkle_branches)
{
    // Reconstruct coinbase from per-connection parts
    std::string coinbase_hex = coinb1 + extranonce1 + extranonce2 + coinb2;
    uint256 merkle_root = reconstruct_merkle_root(coinbase_hex, merkle_branches);

    uint256 prev_hash;
    prev_hash.SetHex(prevhash_hex);

    std::vector<unsigned char> header;
    header.reserve(80);

    header.push_back(static_cast<unsigned char>((version      ) & 0xff));
    header.push_back(static_cast<unsigned char>((version >>  8) & 0xff));
    header.push_back(static_cast<unsigned char>((version >> 16) & 0xff));
    header.push_back(static_cast<unsigned char>((version >> 24) & 0xff));

    header.insert(header.end(), prev_hash.data(), prev_hash.data() + 32);
    header.insert(header.end(), merkle_root.data(), merkle_root.data() + 32);

    // ntime: miner sends as BE hex, header needs LE bytes
    auto ntime_bytes = ParseHex(ntime);
    std::reverse(ntime_bytes.begin(), ntime_bytes.end());
    header.insert(header.end(), ntime_bytes.begin(), ntime_bytes.end());

    // nbits: GBT sends as BE hex, header needs LE bytes
    auto bits_bytes = ParseHex(nbits_hex);
    std::reverse(bits_bytes.begin(), bits_bytes.end());
    header.insert(header.end(), bits_bytes.begin(), bits_bytes.end());

    // nonce: miner sends as BE hex, header needs LE bytes
    auto nonce_bytes = ParseHex(nonce);
    std::reverse(nonce_bytes.begin(), nonce_bytes.end());
    header.insert(header.end(), nonce_bytes.begin(), nonce_bytes.end());

    if (header.size() != 80)
        return 0.0;

    char pow_hash_bytes[32];
    scrypt_1024_1_1_256(reinterpret_cast<const char*>(header.data()), pow_hash_bytes);

    uint256 pow_hash;
    memcpy(pow_hash.begin(), pow_hash_bytes, 32);

    static const double truediffone = 26959535291011309493156476344723991336010898738574164086137773096960.0;
    if (pow_hash.IsNull())
        return 0.0;

    double hash_val = 0.0;
    for (int i = 31; i >= 0; --i)
        hash_val = hash_val * 256.0 + static_cast<double>(pow_hash.data()[i]);

    if (hash_val == 0.0)
        return 0.0;

    return truediffone / hash_val;
}
} // namespace core
