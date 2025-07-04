#pragma once

#include <memory>
#include <string>
#include <functional>
#include <thread>

#include <boost/asio.hpp>
#include <boost/beast.hpp>
#include <nlohmann/json.hpp>
#include <jsonrpccxx/server.hpp>

#include <core/log.hpp>
#include <core/uint256.hpp>

namespace core {

namespace beast = boost::beast;
namespace http = beast::http;
namespace net = boost::asio;
using tcp = net::ip::tcp;

// Forward declarations
class MiningInterface;

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

/// Mining interface that provides RPC methods for miners
class MiningInterface : public jsonrpccxx::JsonRpc2Server
{
public:
    MiningInterface();

    // Core mining methods that miners expect
    nlohmann::json getwork(const std::string& request_id = "");
    nlohmann::json submitwork(const std::string& nonce, const std::string& header, const std::string& mix, const std::string& request_id = "");
    nlohmann::json getblocktemplate(const nlohmann::json& params = nlohmann::json::array(), const std::string& request_id = "");
    nlohmann::json submitblock(const std::string& hex_data, const std::string& request_id = "");
    
    // Pool stats and info methods
    nlohmann::json getinfo(const std::string& request_id = "");
    nlohmann::json getstats(const std::string& request_id = "");
    nlohmann::json getpeerinfo(const std::string& request_id = "");
    
    // Stratum-style methods (for advanced miners)
    nlohmann::json mining_subscribe(const std::string& user_agent = "", const std::string& request_id = "");
    nlohmann::json mining_authorize(const std::string& username, const std::string& password, const std::string& request_id = "");
    nlohmann::json mining_submit(const std::string& username, const std::string& job_id, const std::string& extranonce2, const std::string& ntime, const std::string& nonce, const std::string& request_id = "");

private:
    void setup_methods();
    
    // Internal state
    uint64_t m_work_id_counter;
    std::map<std::string, nlohmann::json> m_active_work;
    
    // TODO: Add connections to actual mining node and coin interface
    // std::shared_ptr<Node> m_node;
    // std::shared_ptr<CoinInterface> m_coin;
};

/// Main Web Server class
class WebServer
{
    net::io_context& ioc_;
    tcp::acceptor acceptor_;
    std::shared_ptr<MiningInterface> mining_interface_;
    std::string bind_address_;
    uint16_t port_;
    bool running_;
    std::thread server_thread_;

public:
    WebServer(net::io_context& ioc, const std::string& address, uint16_t port);
    ~WebServer();

    // Start/stop the server
    bool start();
    void stop();
    
    // Server info
    std::string get_bind_address() const { return bind_address_; }
    uint16_t get_port() const { return port_; }
    bool is_running() const { return running_; }

private:
    void accept_connections();
    void handle_accept(beast::error_code ec, tcp::socket socket);
};

} // namespace core
