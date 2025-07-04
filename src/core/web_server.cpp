#include "web_server.hpp"

#include <iomanip>
#include <sstream>
#include <ctime>

namespace core {

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
MiningInterface::MiningInterface()
    : m_work_id_counter(1)
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
}

nlohmann::json MiningInterface::getwork(const std::string& request_id)
{
    LOG_INFO << "getwork request received";
    
    // TODO: Get actual work from mining node
    // For now, return a stub response
    nlohmann::json work = {
        {"data", "00000001c570c4764025cf068f3f3fba04bde26fb7b449e0bf12523666e49cbdf6aa8b8f00000000"},
        {"target", "00000000ffff0000000000000000000000000000000000000000000000000000"},
        {"hash1", "00000000000000000000000000000000000000000000000000000000000000000000008000000000000000000000000000000000000000000000000000010000"},
        {"midstate", "5f796c4974b00d64ffc22c9a72e96f9b23c57d7d83d0e7d6a34c4e1f5b4c4b8f"}
    };
    
    // Store work for later validation
    std::string work_id = std::to_string(m_work_id_counter++);
    m_active_work[work_id] = work;
    
    LOG_INFO << "Provided work to miner, work_id=" << work_id;
    return work;
}

nlohmann::json MiningInterface::submitwork(const std::string& nonce, const std::string& header, const std::string& mix, const std::string& request_id)
{
    LOG_INFO << "Work submission received - nonce: " << nonce << ", header: " << header.substr(0, 32) << "...";
    
    // TODO: Validate and submit work to mining node
    // For now, always return true (accepted)
    
    LOG_INFO << "Work submission accepted";
    return true;
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
    return {
        {"version", "c2pool/1.0.0"},
        {"protocolversion", 70015},
        {"blocks", 1}, // TODO: Get from actual chain
        {"connections", 0}, // TODO: Get from peer count
        {"difficulty", 1.0},
        {"networkhashps", 0},
        {"poolhashps", 0},
        {"generate", true},
        {"genproclimit", -1},
        {"testnet", false}, // TODO: Get from config
        {"paytxfee", 0.0},
        {"errors", ""}
    };
}

nlohmann::json MiningInterface::getstats(const std::string& request_id)
{
    return {
        {"pool_statistics", {
            {"shares", {
                {"total", 0},
                {"valid", 0},
                {"invalid", 0},
                {"stale", 0}
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
    
    // TODO: Validate username/password
    // For now, authorize everyone
    return true;
}

nlohmann::json MiningInterface::mining_submit(const std::string& username, const std::string& job_id, const std::string& extranonce2, const std::string& ntime, const std::string& nonce, const std::string& request_id)
{
    LOG_INFO << "Stratum mining.submit from " << username << " for job " << job_id;
    
    // TODO: Validate and submit share
    // For now, accept all shares
    return true;
}

/// WebServer Implementation
WebServer::WebServer(net::io_context& ioc, const std::string& address, uint16_t port)
    : ioc_(ioc)
    , acceptor_(ioc)
    , bind_address_(address)
    , port_(port)
    , running_(false)
{
    mining_interface_ = std::make_shared<MiningInterface>();
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
        
        return true;
        
    } catch (const std::exception& e) {
        LOG_ERROR << "Failed to start web server: " << e.what();
        return false;
    }
}

void WebServer::stop()
{
    if (running_) {
        LOG_INFO << "Stopping web server...";
        
        beast::error_code ec;
        acceptor_.close(ec);
        
        running_ = false;
        
        if (server_thread_.joinable()) {
            server_thread_.join();
        }
        
        LOG_INFO << "Web server stopped";
    }
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

} // namespace core
