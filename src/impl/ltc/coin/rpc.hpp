#pragma once

#include "block.hpp"
#include "rpc_data.hpp"
#include "node_interface.hpp"

#include <iostream>

#include <core/uint256.hpp>
#include <core/timer.hpp>

#include <boost/asio.hpp>
#include <boost/beast.hpp>
#include <nlohmann/json.hpp>
#include <jsonrpccxx/client.hpp>

namespace io = boost::asio;
namespace beast = boost::beast;
namespace http = beast::http;

namespace ltc
{

namespace coin
{

struct RPCAuthData;
class NodeRPC : public jsonrpccxx::IClientConnector
{
    const std::string ID = "curltest";
    const jsonrpccxx::version RPC_VER = jsonrpccxx::version::v2;

    const bool IS_TESTNET;
private:
    ltc::interfaces::Node* m_coin;

    io::io_context* m_context;
    beast::tcp_stream m_stream;
    boost::asio::ip::tcp::resolver m_resolver;
    http::request<http::string_body> m_http_request; 

    std::unique_ptr<RPCAuthData> m_auth;
    jsonrpccxx::JsonRpcClient m_client;

    // Reconnection state
    NetService m_address;
    std::string m_userpass;
    bool m_connected = false;
    std::unique_ptr<core::Timer> m_reconnect_timer;

    std::string Send(const std::string &request) override;
    nlohmann::json CallAPIMethod(const std::string& method, const jsonrpccxx::positional_parameter& params = {});

public:
    NodeRPC(io::io_context* context, ltc::interfaces::Node* coin, bool testnet);
    ~NodeRPC();

    void connect(NetService address, std::string userpass);
    void reconnect();
    bool check();
    bool check_blockheader(uint256 header);
    rpc::WorkData getwork(); //coind::getwork_result getwork(coind::TXIDCache &txidcache, const map<uint256, coind::data::tx_type> &known_txs = map<uint256, coind::data::tx_type>());
    void submit_block(BlockType& block, std::string mweb, bool ignore_failure);
    // Submit a pre-serialised block passed in as a hex string (avoids re-packing)
    // Returns true if the daemon accepted the block (result is null), false otherwise.
    bool submit_block_hex(const std::string& block_hex, const std::string& mweb, bool ignore_failure);

    // RPC Methods
    nlohmann::json getblocktemplate(std::vector<std::string> rules);
    nlohmann::json getnetworkinfo();
	nlohmann::json getblockchaininfo();
	nlohmann::json getmininginfo();
	// verbose: true -- json result, false -- hex-encode result;
	nlohmann::json getblockheader(uint256 header, bool verbose = true);
	// verbosity: 0 for hex-encoded data, 1 for a json object, and 2 for json object with transaction data
	nlohmann::json getblock(uint256 blockhash, int verbosity = 1);
	
};

struct RPCAuthData
{
	std::string authorization;
	std::string host;
};

} // namespace coin

} // namespace ltc


