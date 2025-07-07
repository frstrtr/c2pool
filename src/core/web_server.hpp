#pragma once

#include <memory>
#include <string>
#include <functional>
#include <thread>
#include <atomic>
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

// Bring the address validation types into the core namespace for convenience
using Blockchain = c2pool::address::Blockchain;
using Network = c2pool::address::Network;
using AddressValidationResult = c2pool::address::AddressValidationResult;
using BlockchainAddressValidator = c2pool::address::BlockchainAddressValidator;

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
    
    // Stratum-style methods (for advanced miners)
    nlohmann::json mining_subscribe(const std::string& user_agent = "", const std::string& request_id = "");
    nlohmann::json mining_authorize(const std::string& username, const std::string& password, const std::string& request_id = "");
    nlohmann::json mining_submit(const std::string& username, const std::string& job_id, const std::string& extranonce2, const std::string& ntime, const std::string& nonce, const std::string& request_id = "");

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
    double calculate_share_difficulty(const std::string& job_id, const std::string& extranonce2, 
                                     const std::string& ntime, const std::string& nonce) const;
    
    // Payout management methods
    nlohmann::json getpayoutinfo(const std::string& request_id = "");
    nlohmann::json getminerstats(const std::string& request_id = "");
    void set_pool_payout_address(const std::string& address);
    void set_pool_fee_percent(double fee_percent);

private:
    void setup_methods();
    
    // Internal state
    uint64_t m_work_id_counter;
    std::map<std::string, nlohmann::json> m_active_work;
    std::unique_ptr<LitecoinRpcClient> m_rpc_client;
    bool m_testnet;  // Store testnet flag
    Blockchain m_blockchain;  // Store blockchain type
    std::shared_ptr<IMiningNode> m_node;  // Connection to c2pool node for difficulty tracking
    BlockchainAddressValidator m_address_validator;  // New address validator
    std::unique_ptr<c2pool::payout::PayoutManager> m_payout_manager;  // Payout management
    
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
    bool testnet_;
    Blockchain blockchain_;
    std::thread server_thread_;
    std::unique_ptr<StratumServer> stratum_server_;

public:
    WebServer(net::io_context& ioc, const std::string& address, uint16_t port, bool testnet = false);
    WebServer(net::io_context& ioc, const std::string& address, uint16_t port, bool testnet, std::shared_ptr<IMiningNode> node);
    WebServer(net::io_context& ioc, const std::string& address, uint16_t port, bool testnet, std::shared_ptr<IMiningNode> node, Blockchain blockchain);
    ~WebServer();

    // Start/stop the server
    bool start();
    void stop();
    
    // Stratum server control
    bool start_stratum_server();
    void stop_stratum_server();
    bool is_stratum_running() const;
    
    // Server info
    std::string get_bind_address() const { return bind_address_; }
    uint16_t get_port() const { return port_; }
    bool is_running() const { return running_; }

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
    
    // VARDIFF tracking per miner
    double current_difficulty_ = 1.0;
    uint64_t share_count_ = 0;
    uint64_t last_share_time_ = 0;
    uint64_t last_vardiff_adjustment_ = 0;
    double estimated_hashrate_ = 0.0;
    
    // VARDIFF configuration
    static constexpr double VARDIFF_MIN = 1.0;
    static constexpr double VARDIFF_MAX = 65536.0;
    static constexpr uint64_t VARDIFF_RETARGET_INTERVAL = 30; // seconds
    static constexpr uint64_t VARDIFF_TARGET_TIME = 15; // target seconds between shares

public:
    explicit StratumSession(tcp::socket socket, std::shared_ptr<MiningInterface> mining_interface);
    void start();

private:
    std::string generate_subscription_id();
    void read_message();
    void process_message(std::size_t bytes_read);
    
    nlohmann::json handle_subscribe(const nlohmann::json& params, const nlohmann::json& request_id);
    nlohmann::json handle_authorize(const nlohmann::json& params, const nlohmann::json& request_id);
    nlohmann::json handle_submit(const nlohmann::json& params, const nlohmann::json& request_id);
    
    void send_response(const nlohmann::json& response);
    void send_error(int code, const std::string& message, const nlohmann::json& request_id);
    void send_set_difficulty(double difficulty);
    void send_notify_work();
    
    std::string generate_extranonce1();
    
    // VARDIFF methods
    void update_hashrate_estimate(double share_difficulty);
    void check_vardiff_adjustment();
    double calculate_new_difficulty() const;
    uint64_t get_current_time_seconds() const;
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
