#include "web_server.hpp"

// Real coin daemon RPC (optional - only linked when set_coin_rpc() is called)
#include <impl/ltc/coin/rpc.hpp>
#include <impl/ltc/coin/node_interface.hpp>

#include <core/hash.hpp>   // Hash(a,b) double-SHA256 for merkle computation

#include <iomanip>
#include <sstream>
#include <ctime>
#include <chrono>
#include <cmath>
#include <boost/process.hpp>
#include <boost/algorithm/string.hpp>
#include "btclibs/base58.h"

namespace core {

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
    response.set(http::field::server, "c2pool/1.0");
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
            // Handle GET request - return pool info
            nlohmann::json info_response = mining_interface_->getinfo();
            response_body = info_response.dump();
        }
        else if (request_.method() == http::verb::post) {
            // Handle JSON-RPC POST request
            std::string request_body = request_.body();
            LOG_INFO << "Received JSON-RPC request: " << request_body;
            
            response_body = mining_interface_->HandleRequest(request_body);
            
            LOG_INFO << "Sending JSON-RPC response: " << response_body;
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
        return mining_submit(params[0], params[1], params[2], params[3], params[4]);
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
}

// ─── Live coin-daemon integration ────────────────────────────────────────────

void MiningInterface::set_coin_rpc(ltc::coin::NodeRPC* rpc, ltc::interfaces::Node* coin)
{
    m_coin_rpc  = rpc;
    m_coin_node = coin;
    LOG_INFO << "MiningInterface: coin RPC " << (rpc ? "connected" : "disconnected");
}

void MiningInterface::set_on_block_submitted(std::function<void(const std::string&)> fn)
{
    m_on_block_submitted = std::move(fn);
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
        branches.push_back(current[0].GetHex());
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
    const std::vector<std::pair<std::string,uint64_t>>& outputs)
{
    // coinb1 ends just before extranonce1; coinb2 starts just after extranonce2.
    // Complete coinbase = coinb1 + extranonce1(4B) + extranonce2(4B) + coinb2
    //
    // Coinbase tx wire layout:
    //   [version 4B][input_count 1B]
    //   [prev_hash 32B][prev_idx 4B][script_len 1B][coinb1_script][{8B extranonce}][coinb2_script]
    //   [sequence 4B]
    //   [output_count 1B][outputs ...][locktime 4B]

    const int height = tmpl.value("height", 1);
    const std::string height_hex = encode_height_pushdata(height);
    const int height_bytes = static_cast<int>(height_hex.size()) / 2;

    // Arbitrary pool ID marker appended to script after extranonce
    // "/c2pool/" in ASCII = 2f 63 32 70 6f 6f 6c 2f
    const std::string pool_marker = "2f633270 6f6f6c2f";
    std::string pool_marker_stripped;
    for (char c : pool_marker) { if (c != ' ') pool_marker_stripped += c; }
    const int pool_marker_bytes = static_cast<int>(pool_marker_stripped.size()) / 2;

    // Total coinbase script length: height + 8 (extranonce) + pool_marker
    const int script_total = height_bytes + 8 + pool_marker_bytes;

    // Build coinb1 (version + 1 input header up to + including the height encoding)
    std::ostringstream coinb1;
    coinb1 << "01000000"   // version
           << "01"         // 1 input
           // previous output (zeroes for coinbase)
           << "0000000000000000000000000000000000000000000000000000000000000000"
           << "ffffffff"   // previous index
           // script length (varint, 1 byte since script_total < 253)
           << std::hex << std::setfill('0') << std::setw(2) << script_total
           // height encoding (BIP34)
           << height_hex;

    // Build coinb2 (pool marker + sequence + outputs + locktime)
    std::ostringstream coinb2;
    coinb2 << pool_marker_stripped
           << "ffffffff";  // sequence

    // Outputs
    coinb2 << std::hex << std::setfill('0') << std::setw(2) << outputs.size();
    for (const auto& [addr, amount] : outputs) {
        coinb2 << encode_le64(amount);
        // addr is a 40-char hash160 hex (from get_hash160_for_address)
        coinb2 << p2pkh_script(addr);
    }

    coinb2 << "00000000"; // locktime

    return { coinb1.str(), coinb2.str() };
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
        try {
            std::vector<std::pair<std::string,uint64_t>> outputs;
            if (m_payout_manager_ptr) {
                auto alloc = m_payout_manager_ptr->calculate_payout(coinbase_value);
                // Miner/pool portion → node-owner address (or developer address as fallback)
                if (alloc.miner_amount > 0) {
                    std::string addr = m_payout_manager_ptr->get_node_owner_address();
                    if (addr.empty()) addr = m_payout_manager_ptr->get_developer_address();
                    auto h160 = base58check_to_hash160(addr);
                    if (!h160.empty())
                        outputs.push_back({h160, alloc.miner_amount});
                }
                // Developer fee output
                if (alloc.developer_amount > 0 && !alloc.developer_address.empty()) {
                    auto h160 = base58check_to_hash160(alloc.developer_address);
                    if (!h160.empty())
                        outputs.push_back({h160, alloc.developer_amount});
                }
                // Node-owner fee output (separate if different address)
                if (alloc.node_owner_amount > 0 && !alloc.node_owner_address.empty()) {
                    auto h160 = base58check_to_hash160(alloc.node_owner_address);
                    if (!h160.empty())
                        outputs.push_back({h160, alloc.node_owner_amount});
                }
            }
            // Fallback: single output to zero-key (burn) so coinbase is always valid
            if (outputs.empty())
                outputs.push_back({"0000000000000000000000000000000000000000", coinbase_value});

            cb_parts = build_coinbase_parts(wd.m_data, coinbase_value, outputs);
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
        m_work_valid              = true;

        LOG_INFO << "refresh_work: height=" << wd.m_data.value("height", 0)
                 << " txs=" << wd.m_hashes.size()
                 << " latency=" << wd.m_latency << "ms"
                 << " merkle_branches=" << m_cached_merkle_branches.size();
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

// ─────────────────────────────────────────────────────────────────────────────

nlohmann::json MiningInterface::getwork(const std::string& request_id)
{
    LOG_INFO << "getwork request received";
    
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
        
        LOG_INFO << "Using pool difficulty: " << current_difficulty << ", target: " << target_hex.substr(0, 16) << "...";
    } else {
        LOG_WARNING << "No c2pool node connected, using default difficulty: " << current_difficulty;
    }
    
    // Try to get actual work from Litecoin testnet node
    std::string actual_work_data = "00000001c570c4764025cf068f3f3fba04bde26fb7b449e0bf12523666e49cbdf6aa8b8f00000000";
    std::string actual_midstate = "5f796c4974b00d64ffc22c9a72e96f9b23c57d7d83d0e7d6a34c4e1f5b4c4b8f";
    
    if (m_rpc_client && m_rpc_client->is_connected()) {
        // Try to get block template from Litecoin Core
        try {
            std::string template_response = m_rpc_client->execute_cli_command("getblocktemplate");
            if (!template_response.empty()) {
                LOG_INFO << "Retrieved block template from Litecoin Core (testnet)";
                // TODO: Parse template and create proper work data
                // For now, use static data but log that we have connection
            }
        } catch (const std::exception& e) {
            LOG_WARNING << "Failed to get block template: " << e.what();
        }
    }
    
    nlohmann::json work = {
        {"data", actual_work_data},
        {"target", target_hex},
        {"hash1", "00000000000000000000000000000000000000000000000000000000000000000000008000000000000000000000000000000000000000000000000000010000"},
        {"midstate", actual_midstate},
        {"difficulty", current_difficulty}
    };
    
    // Store work for later validation
    std::string work_id = std::to_string(m_work_id_counter++);
    m_active_work[work_id] = work;
    
    LOG_INFO << "Provided work to miner, work_id=" << work_id << ", difficulty=" << current_difficulty;
    return work;
}

nlohmann::json MiningInterface::submitwork(const std::string& nonce, const std::string& header, const std::string& mix, const std::string& request_id)
{
    LOG_INFO << "Work submission received - nonce: " << nonce << ", header: " << header.substr(0, 32) << "...";
    
    // Validate the submitted work
    bool work_valid = true; // TODO: Implement actual validation
    
    if (work_valid && m_node) {
        // Track the mining_share submission for difficulty adjustment
        std::string session_id = "miner_" + std::to_string(m_work_id_counter); // TODO: Use actual session ID
        m_node->track_mining_share_submission(session_id, 1.0); // TODO: Use actual difficulty
        
        // Create a new mining_share and add to the sharechain
        uint256 share_hash;
        share_hash.SetHex(header); // Simplified - would need proper hash calculation
        
        uint256 prev_hash = uint256::ZERO; // TODO: Get from actual previous mining_share
        uint256 target;
        target.SetHex("00000000ffff0000000000000000000000000000000000000000000000000000"); // TODO: Use actual target
        
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

    if (m_coin_rpc) {
        try {
            m_coin_rpc->submit_block_hex(hex_data, "", false);
            LOG_INFO << "Block forwarded to coin daemon";
            // Notify P2P layer with the first 160 hex chars (80-byte header)
            if (m_on_block_submitted && hex_data.size() >= 160) {
                m_on_block_submitted(hex_data.substr(0, 160));
            }
        } catch (const std::exception& e) {
            LOG_ERROR << "submitblock failed: " << e.what();
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
    
    return {
        {"version", "c2pool/1.0.0"},
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
        {"errors", ""}
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

    return {
        {"pool_statistics", {
            {"mining_shares", total_mining_shares},
            {"pool_hashrate", pool_hashrate},
            {"difficulty", difficulty},
            {"block_height", block_height},
            {"connected_peers", connected_peers},
            {"active_miners", active_miners}
        }}
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
    }
    return result;
}

nlohmann::json MiningInterface::mining_subscribe(const std::string& user_agent, const std::string& request_id)
{
    LOG_INFO << "Stratum mining.subscribe from: " << user_agent;
    
    // Return stratum subscription response
    return nlohmann::json::array({
        nlohmann::json::array({"mining.notify", "subscription_id_1"}),
        "extranonce1",
        4 // extranonce2_size
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

nlohmann::json MiningInterface::mining_submit(const std::string& username, const std::string& job_id, const std::string& extranonce2, const std::string& ntime, const std::string& nonce, const std::string& request_id)
{
    LOG_INFO << "Stratum mining.submit from " << username << " for job " << job_id 
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
    double share_difficulty = calculate_share_difficulty(job_id, extranonce2, ntime, nonce);
    
    if (m_solo_mode) {
        // Solo mining mode - work directly with blockchain
        LOG_INFO << "Solo mining share from " << username << " (difficulty: " << share_difficulty << ")";
        
        // In solo mode, check if share meets network difficulty for block submission
        std::string payout_address = m_solo_address.empty() ? username : m_solo_address;
        
        // Calculate payout allocation if we have a payout manager
        if (m_payout_manager_ptr) {
            // Simulate block reward for calculation (25 LTC = 2500000000 satoshis)
            uint64_t block_reward = 2500000000; // 25 LTC in satoshis
            auto allocation = m_payout_manager_ptr->calculate_payout(block_reward);
            
            if (allocation.is_valid()) {
                LOG_INFO << "Solo mining payout allocation:";
                LOG_INFO << "  Miner (" << payout_address << "): " << allocation.miner_percent << "% = " << allocation.miner_amount << " satoshis";
                LOG_INFO << "  Developer: " << allocation.developer_percent << "% = " << allocation.developer_amount << " satoshis (" << allocation.developer_address << ")";
                if (allocation.node_owner_amount > 0) {
                    LOG_INFO << "  Node owner: " << allocation.node_owner_percent << "% = " << allocation.node_owner_amount << " satoshis (" << allocation.node_owner_address << ")";
                }
                
                // TODO: When we find a block, use this allocation to create the coinbase transaction
                // TODO: Include developer fee and node owner fee in the coinbase outputs
            }
        }
        
        LOG_INFO << "Solo mining share accepted - primary payout address: " << payout_address;
        
        // TODO: Check if share meets network difficulty and submit block to blockchain
        // TODO: Implement block template generation with multi-output coinbase (miner + dev + node owner)
        
        return nlohmann::json{{"result", true}};
    } else {
        // Standard pool mode - track shares for sharechain and payouts
        
        // Track mining_share submission for statistics
        if (m_node) {
            // Track the mining_share submission
            m_node->track_mining_share_submission(username, share_difficulty);
            
            // Create mining_share hash for storage (simplified)
            uint256 share_hash;
            std::string hash_input = job_id + extranonce2 + ntime + nonce;
            share_hash.SetHex(hash_input.substr(0, 64)); // Take first 64 chars as hash
            
            LOG_INFO << "Mining share accepted from " << username << " - hash: " << share_hash.ToString().substr(0, 16) << "...";
            
            // Store mining_share in enhanced node (this will go to LevelDB)
            uint256 prev_hash = uint256::ZERO; // TODO: Get actual previous mining_share hash
            uint256 target;
            target.SetHex("00000000ffff0000000000000000000000000000000000000000000000000000");
            
            m_node->add_local_mining_share(share_hash, prev_hash, target);
            
            LOG_INFO << "Mining share stored in sharechain database";
        } else {
            LOG_INFO << "Mining share accepted from " << username << " (no node connected for storage)";
        }
        
        // Record share contribution for payout calculation (pool mode only)
        if (m_payout_manager) {
            m_payout_manager->record_share_contribution(username, share_difficulty);
            LOG_INFO << "Share contribution recorded for payout: " << username << " (difficulty: " << share_difficulty << ")";
        }
        
        // Calculate developer and node owner payouts for pool mode
        if (m_payout_manager_ptr) {
            // Log payout allocation for this share (informational)
            uint64_t simulated_reward = 2500000000; // 25 LTC for calculation
            auto allocation = m_payout_manager_ptr->calculate_payout(simulated_reward);
            
            if (allocation.is_valid()) {
                LOG_INFO << "Pool payout allocation (per block):";
                LOG_INFO << "  Pool miners: " << allocation.miner_percent << "%";
                LOG_INFO << "  Developer fee: " << allocation.developer_percent << "% -> " << allocation.developer_address;
                if (allocation.node_owner_amount > 0) {
                    LOG_INFO << "  Node owner fee: " << allocation.node_owner_percent << "% -> " << allocation.node_owner_address;
                }
            }
        }
        
        return nlohmann::json{{"result", true}};
    }
}

nlohmann::json MiningInterface::validate_address(const std::string& address)
{
    LOG_INFO << "Address validation request for: " << address;
    
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
            
            LOG_INFO << "Address validation result: " << (validation_result.is_valid ? "VALID" : "INVALID");
            
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
    LOG_INFO << "Coinbase validation request - hex length: " << coinbase_hex.length();
    
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
        
        LOG_INFO << "Coinbase validation result: " << (is_valid ? "VALID" : "INVALID");
        
    } catch (const std::exception& e) {
        LOG_ERROR << "Coinbase validation error: " << e.what();
        result["valid"] = false;
        result["error"] = std::string("Validation failed: ") + e.what();
    }
    
    return result;
}

nlohmann::json MiningInterface::getblockcandidate(const nlohmann::json& params)
{
    LOG_INFO << "Block candidate request received";
    
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
            
            LOG_INFO << "Block candidate with payout distribution generated";
        } else {
            base_template["payout_distribution"] = false;
            LOG_INFO << "Basic block candidate generated (no payout distribution)";
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
                try { mining_interface_->refresh_work(); } catch (...) {}
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

void WebServer::set_on_block_submitted(std::function<void(const std::string&)> fn)
{
    mining_interface_->set_on_block_submitted(std::move(fn));
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
    hashrate_tracker_.set_difficulty_bounds(1.0, 65536.0);
    hashrate_tracker_.set_target_time_per_mining_share(15.0);
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
        } else {
            // Unknown method
            send_error(-1, "Unknown method", id);
            return;
        }
        
        send_response(response);
        
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
        nlohmann::json::array({"mining.set_difficulty", subscription_id_}),
        extranonce1_,
        4  // extranonce2_size
    });
    response["error"] = nullptr;
    
    LOG_INFO << "Mining subscription successful for: " << subscription_id_;
    
    // Send initial difficulty from tracker
    send_set_difficulty(hashrate_tracker_.get_current_difficulty());
    
    // Send initial work
    send_notify_work();
    
    return response;
}

nlohmann::json StratumSession::handle_authorize(const nlohmann::json& params, const nlohmann::json& request_id)
{
    if (params.size() >= 1 && params[0].is_string()) {
        username_ = params[0];
        authorized_ = true;
        
        LOG_INFO << "Mining authorization successful for: " << username_;
        
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
    
    // Calculate share difficulty and verify it meets the session target
    double share_difficulty = mining_interface_->calculate_share_difficulty(
        job_id, extranonce2, ntime, nonce);
    double required_difficulty = hashrate_tracker_.get_current_difficulty();
    
    if (share_difficulty < required_difficulty) {
        ++rejected_shares_;
        LOG_WARNING << "Low difficulty share from " << username_
                    << ": got " << share_difficulty << ", need " << required_difficulty;
        nlohmann::json response;
        response["id"] = request_id;
        response["result"] = false;
        response["error"] = nlohmann::json::array({23, "Low difficulty share", nullptr});
        return response;
    }
    
    // Valid share — record and adjust VARDIFF
    ++accepted_shares_;
    double old_difficulty = required_difficulty;
    hashrate_tracker_.record_mining_share_submission(share_difficulty, true);
    
    double new_difficulty = hashrate_tracker_.get_current_difficulty();
    if (new_difficulty != old_difficulty) {
        send_set_difficulty(new_difficulty);
        LOG_INFO << "VARDIFF adjustment for " << username_ << ": "
                 << old_difficulty << " -> " << new_difficulty;
    }
    
    // Forward the accepted share to MiningInterface for block-level checking
    mining_interface_->mining_submit(username_, job_id, extranonce2, ntime, nonce);
    
    LOG_INFO << "Share accepted from " << username_ << " (diff=" << share_difficulty
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

void StratumSession::send_notify_work()
{
    nlohmann::json notification;
    notification["id"] = nullptr;
    notification["method"] = "mining.notify";

    std::string job_id  = "job_" + std::to_string(job_counter_.fetch_add(1));

    // Defaults (used when no live template is available yet)
    std::string prevhash = "0000000000000000000000000000000000000000000000000000000000000000";
    std::string version  = "00000001";
    std::string nbits    = "1d00ffff";
    uint32_t    curtime  = static_cast<uint32_t>(std::time(nullptr));
    nlohmann::json merkle_branches = nlohmann::json::array();
    std::string coinb1 = "01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff";
    std::string coinb2 = "ffffffff0100f2052a010000001976a914000000000000000000000000000000000000000088ac00000000";

    // Override with live block template data if available
    auto tmpl = mining_interface_->get_current_work_template();
    if (!tmpl.empty() && !tmpl.is_null()) {
        if (tmpl.contains("previousblockhash"))
            prevhash = tmpl["previousblockhash"].get<std::string>();

        if (tmpl.contains("version")) {
            std::ostringstream ss;
            ss << std::hex << std::setw(8) << std::setfill('0')
               << tmpl["version"].get<int>();
            version = ss.str();
        }

        if (tmpl.contains("bits"))
            nbits = tmpl["bits"].get<std::string>();

        if (tmpl.contains("curtime"))
            curtime = static_cast<uint32_t>(tmpl["curtime"].get<uint64_t>());

        LOG_INFO << "send_notify_work: live template height="
                 << tmpl.value("height", 0) << " prevhash=" << prevhash.substr(0, 16) << "...";
    } else {
        LOG_WARNING << "send_notify_work: no live template, using placeholder work";
    }

    // Encode curtime as 8-hex-char (4-byte big-endian)
    std::ostringstream ntime_ss;
    ntime_ss << std::hex << std::setw(8) << std::setfill('0') << curtime;
    std::string ntime = ntime_ss.str();

    // Merkle branches = computed tree path (miners concat coinbase_hash+branch each level)
    for (const auto& h : mining_interface_->get_stratum_merkle_branches())
        merkle_branches.push_back(h);

    // Real coinbase parts if available
    auto [cb1, cb2] = mining_interface_->get_coinbase_parts();
    if (!cb1.empty()) {
        coinb1 = std::move(cb1);
        coinb2 = std::move(cb2);
    }

    bool clean_jobs = true;

    // Track this job for stale detection
    if (clean_jobs) {
        active_jobs_.clear();
    }
    // Evict oldest if at capacity
    while (active_jobs_.size() >= MAX_ACTIVE_JOBS) {
        active_jobs_.erase(active_jobs_.begin());
    }
    active_jobs_[job_id] = {prevhash, nbits, curtime};

    notification["params"] = nlohmann::json::array({
        job_id, prevhash, coinb1, coinb2, merkle_branches,
        version, nbits, ntime, clean_jobs
    });

    send_response(notification);
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

double MiningInterface::calculate_share_difficulty(const std::string& job_id, const std::string& extranonce2, 
                                                   const std::string& ntime, const std::string& nonce) const
{
    // For testing, return a fixed difficulty
    // In a real implementation, this would calculate based on the hash result
    return 1.0;
}
} // namespace core
