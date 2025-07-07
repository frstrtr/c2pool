#include "web_server.hpp"

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
    
    // Payout-related methods
    Add("getpayoutinfo", jsonrpccxx::MethodHandle([this](const nlohmann::json& params) -> nlohmann::json {
        return getpayoutinfo("");
    }));
    
    Add("getminerstats", jsonrpccxx::MethodHandle([this](const nlohmann::json& params) -> nlohmann::json {
        return getminerstats("");
    }));
}

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
    
    // TODO: Get actual block template from coin node
    nlohmann::json block_template = {
        {"version", 536870912},
        {"previousblockhash", "00000000000000000000000000000000000000000000000000000000000000000"},
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
    
    return block_template;
}

nlohmann::json MiningInterface::submitblock(const std::string& hex_data, const std::string& request_id)
{
    LOG_INFO << "Block submission received - size: " << hex_data.length() << " chars";
    
    // TODO: Validate and submit block to coin node
    // For now, return null (success)
    
    LOG_INFO << "Block submission accepted";
    return nullptr;
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
    
    return {
        {"version", "c2pool/1.0.0"},
        {"protocolversion", 70015},
        {"blocks", 1}, // TODO: Get from actual chain
        {"connections", connections},
        {"difficulty", current_difficulty},
        {"networkhashps", 0}, // TODO: Get from coin node
        {"poolhashps", pool_hashrate},
        {"poolshares", total_shares}, // Mining shares from physical miners
        {"generate", true},
        {"genproclimit", -1},
        {"testnet", m_testnet}, // Use stored testnet flag
        {"paytxfee", 0.0},
        {"errors", ""}
    };
}

nlohmann::json MiningInterface::getstats(const std::string& request_id)
{
    return {
        {"pool_statistics", {
            {"mining_shares", {  // Shares from physical miners
                {"total", 0},
                {"valid", 0},
                {"invalid", 0},
                {"stale", 0}
            }},
            {"p2p_shares", {  // Shares from cross-node communication
                {"total", 0},
                {"received", 0},
                {"verified", 0},
                {"forwarded", 0}
            }},
            {"pool_hashrate", "0 H/s"},
            {"network_hashrate", "0 H/s"},
            {"difficulty", 1.0},
            {"block_height", 1},
            {"connected_peers", 0},
            {"uptime", 0}
        }}
    };
}

nlohmann::json MiningInterface::getpeerinfo(const std::string& request_id)
{
    // TODO: Get actual peer info from pool node
    return nlohmann::json::array();
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
        // For now, accept all shares and log them for solo mining
        std::string payout_address = m_solo_address.empty() ? username : m_solo_address;
        
        LOG_INFO << "Solo mining share accepted - payout address: " << payout_address;
        
        // TODO: Check if share meets network difficulty and submit block to blockchain
        // TODO: Implement block template generation with payout to solo address
        
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
        
        return nlohmann::json{{"result", true}};
    }
}

bool MiningInterface::is_valid_address(const std::string& address) const
{
    // Use the new blockchain-specific address validator
    AddressValidationResult result = m_address_validator.validate_address_strict(address);
    
    if (result.is_valid) {
        LOG_INFO << "Address validation successful: " << address 
                 << " (blockchain: " << static_cast<int>(result.blockchain)
                 << ", network: " << static_cast<int>(result.network)
                 << ", type: " << static_cast<int>(result.type) << ")";
        return true;
    } else {
        LOG_WARNING << "Address validation failed: " << address 
                   << " - " << result.error_message;
        return false;
    }
}

double MiningInterface::calculate_share_difficulty(const std::string& job_id, const std::string& extranonce2, 
                                                  const std::string& ntime, const std::string& nonce) const
{
    // Create a hash from the submission parameters
    std::string hash_input = job_id + extranonce2 + ntime + nonce;
    
    // For now, calculate a simplified difficulty based on hash characteristics
    // In a real implementation, this would involve proper block header construction
    // and hash calculation, but for pseudo-shares this approximation works
    
    uint64_t hash_value = 0;
    for (size_t i = 0; i < std::min(hash_input.length(), size_t(16)); ++i) {
        if (hash_input[i] >= '0' && hash_input[i] <= '9') {
            hash_value = (hash_value << 4) | (hash_input[i] - '0');
        } else if (hash_input[i] >= 'a' && hash_input[i] <= 'f') {
            hash_value = (hash_value << 4) | (hash_input[i] - 'a' + 10);
        } else if (hash_input[i] >= 'A' && hash_input[i] <= 'F') {
            hash_value = (hash_value << 4) | (hash_input[i] - 'A' + 10);
        }
    }
    
    // Convert to difficulty (simplified calculation)
    // Higher hash values represent easier targets (lower difficulty)
    if (hash_value == 0) {
        return 1.0;
    }
    
    // Calculate difficulty as a function of leading zeros and hash value
    double difficulty = 1.0;
    
    // Count leading zeros in hash_input (hex representation)
    int leading_zeros = 0;
    for (char c : hash_input) {
        if (c == '0') {
            leading_zeros++;
        } else {
            break;
        }
    }
    
    // More leading zeros = higher difficulty
    difficulty = std::pow(16.0, leading_zeros) * (1.0 + (hash_value % 1000) / 1000.0);
    
    // Clamp to reasonable range
    return std::max(0.1, std::min(difficulty, 1000000.0));
}

/// StratumSession Implementation
StratumSession::StratumSession(tcp::socket socket, std::shared_ptr<MiningInterface> mining_interface)
    : socket_(std::move(socket))
    , mining_interface_(mining_interface)
    , subscription_id_(generate_subscription_id())
{
}

void StratumSession::start()
{
    read_message();
}

std::string StratumSession::generate_subscription_id()
{
    static std::atomic<uint64_t> counter{0};
    return "sub_" + std::to_string(++counter);
}

void StratumSession::read_message()
{
    auto self = shared_from_this();
    
    net::async_read_until(socket_, buffer_, "\n",
        [self](beast::error_code ec, std::size_t bytes_transferred)
        {
            if (ec) {
                if (ec != net::error::eof && ec != net::error::operation_aborted) {
                    LOG_ERROR << "Stratum read error: " << ec.message();
                }
                return;
            }
            
            self->process_message(bytes_transferred);
        });
}

void StratumSession::process_message(std::size_t bytes_read)
{
    try {
        std::istream is(&buffer_);
        std::string line;
        std::getline(is, line);
        
        // Remove carriage return if present
        if (!line.empty() && line.back() == '\r') {
            line.pop_back();
        }
        
        if (line.empty()) {
            read_message(); // Continue reading
            return;
        }
        
        LOG_INFO << "Stratum received: " << line;
        
        // Parse JSON message
        nlohmann::json request = nlohmann::json::parse(line);
        
        // Validate message format
        if (!request.contains("id") || !request.contains("method")) {
            send_error(-32600, "Invalid Request", request.value("id", nullptr));
            read_message();
            return;
        }
        
        std::string method = request["method"];
        nlohmann::json params = request.value("params", nlohmann::json::array());
        auto request_id = request["id"];
        
        // Route message to appropriate handler
        nlohmann::json response;
        
        if (method == "mining.subscribe") {
            response = handle_subscribe(params, request_id);
        } else if (method == "mining.authorize") {
            response = handle_authorize(params, request_id);
        } else if (method == "mining.submit") {
            response = handle_submit(params, request_id);
        } else {
            send_error(-32601, "Method not found", request_id);
            read_message();
            return;
        }
        
        send_response(response);
        read_message(); // Continue reading
        
    } catch (const std::exception& e) {
        LOG_ERROR << "Stratum message processing error: " << e.what();
        send_error(-32700, "Parse error", nullptr);
        read_message();
    }
}

nlohmann::json StratumSession::handle_subscribe(const nlohmann::json& params, const nlohmann::json& request_id)
{
    std::string user_agent = "unknown";
    if (params.is_array() && !params.empty() && params[0].is_string()) {
        user_agent = params[0];
    }
    
    LOG_INFO << "Stratum mining.subscribe from: " << user_agent << " (session: " << subscription_id_ << ")";
    
    // Generate subscription details
    nlohmann::json subscriptions = nlohmann::json::array({
        nlohmann::json::array({"mining.set_difficulty", subscription_id_}),
        nlohmann::json::array({"mining.notify", subscription_id_})
    });
    
    std::string extranonce1 = generate_extranonce1();
    int extranonce2_size = 4;
    
    nlohmann::json result = nlohmann::json::array({
        subscriptions,
        extranonce1,
        extranonce2_size
    });
    
    // Store session info
    extranonce1_ = extranonce1;
    subscribed_ = true;
    
    return {
        {"id", request_id},
        {"result", result},
        {"error", nullptr}
    };
}

nlohmann::json StratumSession::handle_authorize(const nlohmann::json& params, const nlohmann::json& request_id)
{
    if (!params.is_array() || params.size() < 2) {
        return {
            {"id", request_id},
            {"result", nullptr},
            {"error", {{"code", -1}, {"message", "Invalid params"}}}
        };
    }
    
    std::string username = params[0];
    std::string password = params[1];
    
    LOG_INFO << "Stratum mining.authorize for user: " << username << " (session: " << subscription_id_ << ")";
    
    // Check if blockchain is synchronized before allowing mining
    if (!mining_interface_->is_blockchain_synced()) {
        mining_interface_->log_sync_progress();
        LOG_WARNING << "Rejecting mining.authorize - blockchain not synchronized";
        return {
            {"id", request_id},
            {"result", false},
            {"error", {{"code", -2}, {"message", "Pool not ready - blockchain synchronizing"}}}
        };
    }
    
    // Validate address for the configured blockchain
    AddressValidationResult validation_result = mining_interface_->get_address_validator().validate_address_strict(username);
    if (!validation_result.is_valid) {
        std::string blockchain_name = "Unknown";
        switch (mining_interface_->get_blockchain()) {
            case Blockchain::LITECOIN: blockchain_name = "Litecoin"; break;
            case Blockchain::BITCOIN: blockchain_name = "Bitcoin"; break;
            case Blockchain::ETHEREUM: blockchain_name = "Ethereum"; break;
            case Blockchain::MONERO: blockchain_name = "Monero"; break;
            case Blockchain::ZCASH: blockchain_name = "Zcash"; break;
            case Blockchain::DOGECOIN: blockchain_name = "Dogecoin"; break;
        }
        
        std::string network_name = mining_interface_->get_network() == Network::TESTNET ? "testnet" : "mainnet";
        
        LOG_WARNING << "Invalid " << blockchain_name << " address in mining.authorize: " << username 
                   << " - " << validation_result.error_message;
        return {
            {"id", request_id},
            {"result", false},
            {"error", {{"code", -1}, {"message", "Invalid " + blockchain_name + " " + network_name + " address: " + validation_result.error_message}}}
        };
    }
    
    // Store authorized user
    authorized_ = true;
    username_ = username;
    
    // Return success response first
    nlohmann::json success_response = {
        {"id", request_id},
        {"result", true},
        {"error", nullptr}
    };
    
    // Queue initial difficulty and work to be sent after this response
    // Note: These will be sent by the session handler after sending this response
    need_initial_setup_ = true;
    
    return success_response;
}

nlohmann::json StratumSession::handle_submit(const nlohmann::json& params, const nlohmann::json& request_id)
{
    if (!authorized_) {
        return {
            {"id", request_id},
            {"result", false},
            {"error", {{"code", -1}, {"message", "Not authorized"}}}
        };
    }
    
    if (!params.is_array() || params.size() < 5) {
        return {
            {"id", request_id},
            {"result", false},
            {"error", {{"code", -1}, {"message", "Invalid params"}}}
        };
    }
    
    std::string username = params[0];
    std::string job_id = params[1];
    std::string extranonce2 = params[2];
    std::string ntime = params[3];
    std::string nonce = params[4];
    
    LOG_INFO << "Stratum mining.submit from " << username << " for job " << job_id 
             << " (session: " << subscription_id_ << ", difficulty: " << current_difficulty_ << ")";
    
    // Update VARDIFF tracking - treat all submissions as pseudo-shares
    update_hashrate_estimate(current_difficulty_);
    
    // Validate submission via mining interface
    bool accepted = mining_interface_->mining_submit(username, job_id, extranonce2, ntime, nonce, "stratum")["result"].get<bool>();
    
    // Check if VARDIFF adjustment is needed
    check_vardiff_adjustment();
    
    return {
        {"id", request_id},
        {"result", accepted},
        {"error", nullptr}
    };
}

void StratumSession::send_response(const nlohmann::json& response)
{
    std::string message = response.dump() + "\n";
    
    auto self = shared_from_this();
    net::async_write(socket_, net::buffer(message),
        [self, message](beast::error_code ec, std::size_t)
        {
            if (ec) {
                LOG_ERROR << "Stratum write error: " << ec.message();
                return;
            }
            
            // After successfully sending the authorization response,
            // send initial setup if needed
            if (self->need_initial_setup_) {
                self->need_initial_setup_ = false;
                self->send_set_difficulty(self->current_difficulty_);
                self->send_notify_work();
            }
        });
}

void StratumSession::send_error(int code, const std::string& message, const nlohmann::json& request_id)
{
    nlohmann::json error_response = {
        {"id", request_id},
        {"result", nullptr},
        {"error", {{"code", code}, {"message", message}}}
    };
    
    send_response(error_response);
}

void StratumSession::send_set_difficulty(double difficulty)
{
    nlohmann::json notification = {
        {"id", nullptr},
        {"method", "mining.set_difficulty"},
        {"params", nlohmann::json::array({difficulty})}
    };
    
    send_response(notification);
}

void StratumSession::send_notify_work()
{
    // Generate work notification
    std::string job_id = "job_" + std::to_string(++job_counter_);
    std::string prevhash = "00000000000000000000000000000000000000000000000000000000000000000";
    std::string coinb1 = "01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff";
    
    // Build coinbase output with proper payout address
    std::string coinb2;
    if (mining_interface_ && mining_interface_->get_payout_manager()) {
        // Use payout manager to build coinbase with proper reward distribution
        uint64_t block_reward = 5000000000ULL; // 50 LTC in satoshis (testnet)
        coinb2 = mining_interface_->get_payout_manager()->build_coinbase_output(block_reward, username_);
    } else {
        // Fallback to simple coinbase with miner's address if available
        coinb2 = "ffffffff0100f2052a010000001976a914";
        if (!username_.empty()) {
            // In a real implementation, would decode the address to get the hash160
            // For now, use placeholder but log the intended payout address
            LOG_INFO << "Building coinbase for payout address: " << username_;
        }
        coinb2 += "89abcdefabbaabbaabbaabbaabbaabbaabbaabba88ac"; // Placeholder hash + script end
    }
    
    std::string version = "00000001";
    std::string nbits = "1d00ffff";
    std::string ntime = std::to_string(static_cast<uint32_t>(std::time(nullptr)));
    bool clean_jobs = true;
    
    nlohmann::json notification = {
        {"id", nullptr},
        {"method", "mining.notify"},
        {"params", nlohmann::json::array({
            job_id,
            prevhash,
            coinb1,
            coinb2,
            nlohmann::json::array(), // merkle_branch
            version,
            nbits,
            ntime,
            clean_jobs
        })}
    };
    
    send_response(notification);
}

std::string StratumSession::generate_extranonce1()
{
    static std::atomic<uint32_t> counter{0};
    uint32_t value = ++counter;
    
    std::stringstream ss;
    ss << std::hex << std::setfill('0') << std::setw(8) << value;
    return ss.str();
}

// VARDIFF Implementation
void StratumSession::update_hashrate_estimate(double share_difficulty)
{
    uint64_t current_time = get_current_time_seconds();
    
    if (last_share_time_ > 0) {
        uint64_t time_diff = current_time - last_share_time_;
        if (time_diff > 0) {
            // Calculate hashrate based on difficulty and time
            // hashrate = difficulty * 2^32 / time_to_find
            double hashrate = (share_difficulty * 4294967296.0) / static_cast<double>(time_diff);
            
            // Use exponential moving average for smoothing
            if (estimated_hashrate_ == 0.0) {
                estimated_hashrate_ = hashrate;
            } else {
                estimated_hashrate_ = (estimated_hashrate_ * 0.8) + (hashrate * 0.2);
            }
            
            LOG_INFO << "Miner " << username_ << " hashrate estimate: " 
                     << std::fixed << std::setprecision(2) << (estimated_hashrate_ / 1000000.0) << " MH/s"
                     << " (difficulty: " << share_difficulty << ", time: " << time_diff << "s)";
        }
    }
    
    last_share_time_ = current_time;
    share_count_++;
}

void StratumSession::check_vardiff_adjustment()
{
    uint64_t current_time = get_current_time_seconds();
    
    // Only adjust after initial shares and minimum interval
    if (share_count_ < 3 || 
        current_time - last_vardiff_adjustment_ < VARDIFF_RETARGET_INTERVAL) {
        return;
    }
    
    double new_difficulty = calculate_new_difficulty();
    
    // Apply some damping to prevent oscillation
    if (std::abs(new_difficulty - current_difficulty_) / current_difficulty_ > 0.1) {
        // Limit change rate to prevent shock
        if (new_difficulty > current_difficulty_) {
            new_difficulty = std::min(new_difficulty, current_difficulty_ * 2.0);
        } else {
            new_difficulty = std::max(new_difficulty, current_difficulty_ * 0.5);
        }
        
        // Clamp to min/max bounds
        new_difficulty = std::max(VARDIFF_MIN, std::min(VARDIFF_MAX, new_difficulty));
        
        if (std::abs(new_difficulty - current_difficulty_) > 0.001) {
            LOG_INFO << "VARDIFF adjustment for " << username_ 
                    << " from " << current_difficulty_ << " to " << new_difficulty
                    << " (estimated hashrate: " << std::fixed << std::setprecision(2) 
                    << (estimated_hashrate_ / 1000000.0) << " MH/s)";
            
            current_difficulty_ = new_difficulty;
            send_set_difficulty(new_difficulty);
            last_vardiff_adjustment_ = current_time;
        }
    }
}

double StratumSession::calculate_new_difficulty() const
{
    if (estimated_hashrate_ <= 0.0) {
        return current_difficulty_;
    }
    
    // Calculate difficulty needed to achieve target time between shares
    // target_difficulty = hashrate * target_time / 2^32
    double target_difficulty = (estimated_hashrate_ * VARDIFF_TARGET_TIME) / 4294967296.0;
    
    return target_difficulty;
}

uint64_t StratumSession::get_current_time_seconds() const
{
    return std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
}

/// StratumServer Implementation
StratumServer::StratumServer(net::io_context& ioc, const std::string& address, uint16_t port, std::shared_ptr<MiningInterface> mining_interface)
    : ioc_(ioc)
    , acceptor_(ioc)
    , bind_address_(address)
    , port_(port)
    , mining_interface_(mining_interface)
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
        tcp::endpoint endpoint{net::ip::make_address(bind_address_), port_};
        
        acceptor_.open(endpoint.protocol());
        acceptor_.set_option(net::socket_base::reuse_address(true));
        acceptor_.bind(endpoint);
        acceptor_.listen(net::socket_base::max_listen_connections);
        
        LOG_INFO << "Stratum server listening on " << bind_address_ << ":" << port_;
        
        accept_connections();
        running_ = true;
        
        return true;
        
    } catch (const std::exception& e) {
        LOG_ERROR << "Failed to start Stratum server: " << e.what();
        return false;
    }
}

void StratumServer::stop()
{
    if (running_) {
        LOG_INFO << "Stopping Stratum server...";
        
        beast::error_code ec;
        acceptor_.close(ec);
        
        running_ = false;
        
        LOG_INFO << "Stratum server stopped";
    }
}

void StratumServer::accept_connections()
{
    acceptor_.async_accept(
        [this](beast::error_code ec, tcp::socket socket)
        {
            handle_accept(ec, std::move(socket));
        });
}

void StratumServer::handle_accept(beast::error_code ec, tcp::socket socket)
{
    if (ec) {
        if (ec != net::error::operation_aborted) {
            LOG_ERROR << "Stratum accept error: " << ec.message();
        }
        return;
    }
    
    // Create and start Stratum session
    std::make_shared<StratumSession>(std::move(socket), mining_interface_)->start();
    
    // Continue accepting connections
    accept_connections();
}

/// WebServer Implementation
WebServer::WebServer(net::io_context& ioc, const std::string& address, uint16_t port, bool testnet)
    : ioc_(ioc)
    , acceptor_(ioc)
    , bind_address_(address)
    , port_(port)
    , stratum_port_(8080)  // Default C2Pool Stratum port
    , running_(false)
    , testnet_(testnet)
    , blockchain_(Blockchain::LITECOIN)  // Default to Litecoin for backward compatibility
    , solo_mode_(false)
    , solo_address_("")
{
    mining_interface_ = std::make_shared<MiningInterface>(testnet, nullptr, blockchain_);
    
    // Create Stratum server with explicit port configuration
    stratum_server_ = std::make_unique<StratumServer>(ioc, address, stratum_port_, mining_interface_);
}

WebServer::WebServer(net::io_context& ioc, const std::string& address, uint16_t port, bool testnet, std::shared_ptr<IMiningNode> node)
    : ioc_(ioc)
    , acceptor_(ioc)
    , bind_address_(address)
    , port_(port)
    , stratum_port_(8080)  // Default C2Pool Stratum port
    , running_(false)
    , testnet_(testnet)
    , blockchain_(Blockchain::LITECOIN)  // Default to Litecoin for backward compatibility
    , solo_mode_(false)
    , solo_address_("")
{
    mining_interface_ = std::make_shared<MiningInterface>(testnet, node, blockchain_);
    
    // Create Stratum server with explicit port configuration
    stratum_server_ = std::make_unique<StratumServer>(ioc, address, stratum_port_, mining_interface_);
}

WebServer::WebServer(net::io_context& ioc, const std::string& address, uint16_t port, bool testnet, std::shared_ptr<IMiningNode> node, Blockchain blockchain)
    : ioc_(ioc)
    , acceptor_(ioc)
    , bind_address_(address)
    , port_(port)
    , stratum_port_(8080)  // Default C2Pool Stratum port
    , running_(false)
    , testnet_(testnet)
    , blockchain_(blockchain)
    , solo_mode_(false)
    , solo_address_("")
{
    mining_interface_ = std::make_shared<MiningInterface>(testnet, node, blockchain);
    
    // Create Stratum server with explicit port configuration
    stratum_server_ = std::make_unique<StratumServer>(ioc, address, stratum_port_, mining_interface_);
}

WebServer::~WebServer()
{
    stop();
}

bool WebServer::start()
{
    try {
        tcp::endpoint endpoint{net::ip::make_address(bind_address_), port_};
        
        acceptor_.open(endpoint.protocol());
        acceptor_.set_option(net::socket_base::reuse_address(true));
        acceptor_.bind(endpoint);
        acceptor_.listen(net::socket_base::max_listen_connections);
        
        LOG_INFO << "Web server listening on " << bind_address_ << ":" << port_;
        
        accept_connections();
        running_ = true;
        
        // Start Stratum server if blockchain is synced
        if (mining_interface_->is_blockchain_synced()) {
            LOG_INFO << "Blockchain is synced, starting Stratum server";
            if (!start_stratum_server()) {
                LOG_WARNING << "Failed to start Stratum server";
            }
        } else {
            LOG_INFO << "Stratum server will start once blockchain is synchronized";
        }
        
        return true;
        
    } catch (const std::exception& e) {
        LOG_ERROR << "Failed to start web server: " << e.what();
        return false;
    }
}

bool WebServer::start_solo()
{
    try {
        LOG_INFO << "Starting C2Pool in SOLO mining mode";
        
        // Enable solo mode on the mining interface
        mining_interface_->set_solo_mode(true);
        if (!solo_address_.empty()) {
            mining_interface_->set_solo_address(solo_address_);
            LOG_INFO << "Solo mining configured with payout address: " << solo_address_;
        }
        
        // Start only the Stratum server for solo mining (no HTTP server)
        if (!start_stratum_server()) {
            LOG_ERROR << "Failed to start Stratum server for solo mining";
            return false;
        }
        
        running_ = true;
        LOG_INFO << "SOLO mining mode started successfully";
        LOG_INFO << "Connect your miner to: stratum+tcp://" << bind_address_ << ":" << stratum_port_;
        
        return true;
        
    } catch (const std::exception& e) {
        LOG_ERROR << "Failed to start solo mining mode: " << e.what();
        return false;
    }
}

void WebServer::stop()
{
    if (running_) {
        LOG_INFO << "Stopping web server...";
        
        // Stop Stratum server first
        if (stratum_server_) {
            stratum_server_->stop();
        }
        
        beast::error_code ec;
        acceptor_.close(ec);
        
        running_ = false;
        
        if (server_thread_.joinable()) {
            server_thread_.join();
        }
        
        LOG_INFO << "Web server stopped";
    }
}

bool WebServer::start_stratum_server()
{
    if (!stratum_server_) {
        LOG_ERROR << "Stratum server not initialized";
        return false;
    }
    
    if (stratum_server_->is_running()) {
        LOG_INFO << "Stratum server is already running";
        return true;
    }
    
    if (!stratum_server_->start()) {
        LOG_ERROR << "Failed to start Stratum server";
        return false;
    }
    
    LOG_INFO << "Stratum server started successfully on " << bind_address_ << ":" << stratum_port_;
    return true;
}

void WebServer::stop_stratum_server()
{
    if (stratum_server_ && stratum_server_->is_running()) {
        LOG_INFO << "Stopping Stratum server...";
        stratum_server_->stop();
    }
}

bool WebServer::is_stratum_running() const
{
    return stratum_server_ && stratum_server_->is_running();
}

void WebServer::set_stratum_port(uint16_t port)
{
    stratum_port_ = port;
    // Recreate the Stratum server with the new port
    if (stratum_server_) {
        bool was_running = stratum_server_->is_running();
        if (was_running) {
            stratum_server_->stop();
        }
        stratum_server_ = std::make_unique<StratumServer>(ioc_, bind_address_, stratum_port_, mining_interface_);
        if (was_running) {
            stratum_server_->start();
        }
    }
}

uint16_t WebServer::get_stratum_port() const
{
    return stratum_port_;
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
    if (ec) {
        if (ec != net::error::operation_aborted) {
            LOG_ERROR << "Accept error: " << ec.message();
        }
        return;
    }
    
    // Create and start HTTP session
    std::make_shared<HttpSession>(std::move(socket), mining_interface_)->run();
    
    // Continue accepting connections
    accept_connections();
}

/// LitecoinRpcClient Implementation
LitecoinRpcClient::LitecoinRpcClient(bool testnet) : testnet_(testnet)
{
}

std::string LitecoinRpcClient::execute_cli_command(const std::string& command)
{
    try {
        namespace bp = boost::process;
        
        std::string full_command = "litecoin-cli";
        if (testnet_) {
            full_command += " -testnet";
        }
        full_command += " " + command;
        
        bp::ipstream pipe_stream;
        bp::child c(full_command, bp::std_out > pipe_stream);
        
        std::string result;
        std::string line;
        while (pipe_stream && std::getline(pipe_stream, line) && !line.empty()) {
            result += line + "\n";
        }
        
        c.wait();
        
        if (c.exit_code() != 0) {
            return "";
        }
        
        return result;
    } catch (const std::exception& e) {
        LOG_ERROR << "Failed to execute litecoin-cli command: " << e.what();
        return "";
    }
}

LitecoinRpcClient::SyncStatus LitecoinRpcClient::get_sync_status()
{
    SyncStatus status;
    status.is_synced = false;
    status.progress = 0.0;
    status.current_blocks = 0;
    status.total_headers = 0;
    status.initial_block_download = true;
    
    try {
        std::string response = execute_cli_command("getblockchaininfo");
        if (response.empty()) {
            status.error_message = "Failed to connect to Litecoin Core";
            return status;
        }
        
        nlohmann::json info = nlohmann::json::parse(response);
        
        status.current_blocks = info.value("blocks", 0);
        status.total_headers = info.value("headers", 0);
        status.progress = info.value("verificationprogress", 0.0);
        status.initial_block_download = info.value("initialblockdownload", true);
        
        // Consider synced if:
        // 1. Not in initial block download
        // 2. Verification progress > 99.9%
        // 3. Blocks are close to headers (within 2 blocks)
        status.is_synced = !status.initial_block_download && 
                          status.progress > 0.999 && 
                          (status.total_headers - status.current_blocks) <= 2;
        
    } catch (const std::exception& e) {
        status.error_message = "Failed to parse blockchain info: " + std::string(e.what());
    }
    
    return status;
}

bool LitecoinRpcClient::is_connected()
{
    std::string response = execute_cli_command("getnetworkinfo");
    return !response.empty();
}

bool MiningInterface::is_blockchain_synced() const
{
    if (!m_rpc_client) {
        LOG_WARNING << "No RPC client available for sync check";
        return false;
    }
    
    // First check if we can connect to the node
    if (!m_rpc_client->is_connected()) {
        LOG_WARNING << "Cannot connect to Litecoin Core";
        return false;
    }
    
    auto status = m_rpc_client->get_sync_status();
    
    if (!status.error_message.empty()) {
        LOG_WARNING << "Sync status check failed: " << status.error_message;
        return false;
    }
    
    if (status.is_synced) {
        LOG_INFO << "Blockchain is fully synced (blocks: " << status.current_blocks 
                 << ", headers: " << status.total_headers 
                 << ", progress: " << (status.progress * 100.0) << "%)";
        return true;
    } else {
        LOG_INFO << "Blockchain is still syncing (blocks: " << status.current_blocks 
                 << "/" << status.total_headers 
                 << ", progress: " << (status.progress * 100.0) << "%)";
        return false;
    }
}

void MiningInterface::log_sync_progress() const
{
    if (!m_rpc_client) {
        LOG_WARNING << "No RPC client available for sync status";
        return;
    }
    
    auto status = m_rpc_client->get_sync_status();
    
    if (!status.error_message.empty()) {
        LOG_ERROR << "Sync status error: " << status.error_message;
        return;
    }
    
    if (status.is_synced) {
        LOG_INFO << "Blockchain is fully synchronized - Ready for mining!";
    } else {
        double progress_percent = status.progress * 100.0;
        LOG_INFO << "Blockchain sync progress: " << std::fixed << std::setprecision(2) 
                 << progress_percent << "% (" << status.current_blocks << "/" 
                 << status.total_headers << " blocks)";
        
        if (status.initial_block_download) {
            LOG_INFO << "Initial block download in progress...";
        }
    }
}

// Payout-related API methods
nlohmann::json MiningInterface::getpayoutinfo(const std::string& request_id)
{
    LOG_INFO << "getpayoutinfo request received";
    
    if (!m_payout_manager) {
        return nlohmann::json{
            {"error", "Payout manager not initialized"},
            {"pool_fee_percent", 0.0},
            {"active_miners", 0},
            {"total_difficulty", 0.0}
        };
    }
    
    auto stats = m_payout_manager->get_payout_statistics();
    stats["method"] = "getpayoutinfo";
    return stats;
}

nlohmann::json MiningInterface::getminerstats(const std::string& request_id)
{
    LOG_INFO << "getminerstats request received";
    
    if (!m_payout_manager) {
        return nlohmann::json{
            {"error", "Payout manager not initialized"},
            {"miners", nlohmann::json::array()}
        };
    }
    
    auto stats = m_payout_manager->get_payout_statistics();
    
    nlohmann::json result;
    result["method"] = "getminerstats";
    result["active_miners"] = stats["active_miners"];
    result["miners"] = stats["miners"];
    result["pool_fee_percent"] = stats["pool_fee_percent"];
    
    return result;
}

void MiningInterface::set_pool_payout_address(const std::string& address)
{
    if (m_payout_manager) {
        m_payout_manager->set_primary_pool_address(address);
        LOG_INFO << "Pool payout address set to: " << address;
    }
}

void MiningInterface::set_pool_fee_percent(double fee_percent)
{
    if (m_payout_manager) {
        m_payout_manager->set_pool_fee_percent(fee_percent);
        LOG_INFO << "Pool fee percent set to: " << fee_percent << "%";
    }
}

} // namespace core
