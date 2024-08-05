#pragma once

#include "block.hpp"

#include <iostream>

#include <core/uint256.hpp>

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

private:
    io::io_context* m_context;
    beast::tcp_stream m_stream;
    boost::asio::ip::tcp::resolver m_resolver;
    http::request<http::string_body> m_http_request; 

    std::unique_ptr<RPCAuthData> m_auth;
    jsonrpccxx::JsonRpcClient m_client;

    nlohmann::json CallAPIMethod(const std::string& method, const jsonrpccxx::positional_parameter& params = {});

public:
    NodeRPC(io::io_context* context, RPCAuthData auth, const char* login);
    ~NodeRPC();

    // TODO: update for async (maybe c++20 coroutines)
    bool check();
    bool check_blockheader(uint256 header);
    // TODO: void getwork(); //coind::getwork_result getwork(coind::TXIDCache &txidcache, const map<uint256, coind::data::tx_type> &known_txs = map<uint256, coind::data::tx_type>());
    void submit_block(BlockType& block); //TODO: p2p node; void submit_block(coind::data::types::BlockType &block, std::string mweb, /*bool use_getblocktemplate,*/ bool ignore_failure, bool segwit_activated);

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
	const char *ip;
	const char *port;
	char *authorization; //TODO: char* -> std::string?
	char *host;          //TODO: char* -> std::string?

	RPCAuthData() = default;
	RPCAuthData(const char *_ip, const char *_port) : ip(_ip), port(_port)
	{
		
	}
};

} // namespace coin

} // namespace ltc


/*
TODO:
template RPC node?

class RPCNode : public jsonrpccxx::IClientConnector
{
    const std::string ID = "curltest";
    const jsonrpccxx::version RPC_VER = jsonrpccxx::version::v2;

private:
    io::io_context* m_context;
    beast::tcp_stream m_stream;
    boost::asio::ip::tcp::resolver m_resolver;
    http::request<http::string_body> m_http_request; 

    RPCAuthData m_auth;
    jsonrpccxx::JsonRpcClient m_client;

    nlohmann::json CallAPIMethod(const std::string& method, const jsonrpccxx::positional_parameter& params = {});

public:
    RPCNode(io::io_context* context, RPCAuthData auth, const char* login)
        : m_context(context), m_resolver(*context), m_stream(*context),
        m_client(*this, RPC_VER), m_auth(auth)
    {
        m_http_request = {http::verb::post, "/", 11};

        m_auth.host = new char[strlen(m_auth.ip) + strlen(m_auth.port) + 2];
        sprintf(m_auth.host, "%s:%s", m_auth.ip, m_auth.port);
        m_http_request.set(http::field::host, m_auth.host);

        m_http_request.set(http::field::user_agent, BOOST_BEAST_VERSION_STRING);
        m_http_request.set(http::field::content_type, "application/json");

        char *encoded_login = new char[32];
        boost::beast::detail::base64::encode(encoded_login, login, strlen(login));
        m_auth.authorization = new char[6 + strlen(encoded_login) + 1];
        sprintf(m_auth.authorization, "Basic %s", encoded_login);
        m_http_request.set(http::field::authorization, m_auth.authorization);
        delete[] encoded_login;
    }

    ~RPCNode()
    {
        beast::error_code ec;
		m_stream.socket().shutdown(io::ip::tcp::socket::shutdown_both, ec);
		if (ec)
		{
			//TODO:
		}

		delete[] m_auth.host;
		delete[] m_auth.authorization;
    }
};

*/