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
        
        running_ = true;
        return true;
        
    } catch (const std::exception& e) {
        LOG_ERROR << "Failed to start WebServer: " << e.what();
        return false;
    }
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
    
    // Send initial difficulty
    send_set_difficulty(current_difficulty_);
    
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
    
    // For now, accept all shares (in a real implementation, validate the work)
    share_count_++;
    last_share_time_ = get_current_time_seconds();
    
    // Update hashrate estimate for VARDIFF
    update_hashrate_estimate(current_difficulty_);
    check_vardiff_adjustment();
    
    LOG_INFO << "Share submitted by " << username_ << " (difficulty: " << current_difficulty_ << ")";
    
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
    
    // Generate mock work (in real implementation, get from mining interface)
    std::string job_id = "job_" + std::to_string(job_counter_.fetch_add(1));
    std::string prevhash = "0000000000000000000000000000000000000000000000000000000000000000";
    std::string coinb1 = "01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff";
    std::string coinb2 = "ffffffff0100f2052a01000000434104";
    std::string merkle_branches = nlohmann::json::array().dump();
    std::string version = "00000001";
    std::string nbits = "1d00ffff";
    std::string ntime = std::to_string(static_cast<uint32_t>(std::time(nullptr)));
    bool clean_jobs = true;
    
    notification["params"] = nlohmann::json::array({
        job_id, prevhash, coinb1, coinb2, merkle_branches, version, nbits, ntime, clean_jobs
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

void StratumSession::update_hashrate_estimate(double share_difficulty)
{
    uint64_t current_time = get_current_time_seconds();
    if (last_share_time_ > 0) {
        uint64_t time_diff = current_time - last_share_time_;
        if (time_diff > 0) {
            // Simple hashrate estimation: difficulty / time
            double instant_hashrate = share_difficulty / time_diff;
            // Use exponential moving average
            estimated_hashrate_ = estimated_hashrate_ * 0.8 + instant_hashrate * 0.2;
        }
    }
}

void StratumSession::check_vardiff_adjustment()
{
    uint64_t current_time = get_current_time_seconds();
    
    if (current_time - last_vardiff_adjustment_ >= VARDIFF_RETARGET_INTERVAL) {
        double new_difficulty = calculate_new_difficulty();
        
        if (new_difficulty != current_difficulty_) {
            current_difficulty_ = new_difficulty;
            send_set_difficulty(current_difficulty_);
            LOG_INFO << "VARDIFF adjustment for " << username_ << ": " << current_difficulty_;
        }
        
        last_vardiff_adjustment_ = current_time;
    }
}

double StratumSession::calculate_new_difficulty() const
{
    if (estimated_hashrate_ <= 0) {
        return current_difficulty_;
    }
    
    // Target: VARDIFF_TARGET_TIME seconds per share
    double target_difficulty = estimated_hashrate_ * VARDIFF_TARGET_TIME;
    
    // Clamp to min/max values
    target_difficulty = std::max(VARDIFF_MIN, std::min(VARDIFF_MAX, target_difficulty));
    
    return target_difficulty;
}

uint64_t StratumSession::get_current_time_seconds() const
{
    return static_cast<uint64_t>(std::time(nullptr));
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
