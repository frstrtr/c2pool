#pragma once

#include "txidcache.h"
#include "results.h"

#include "jsonrpccxx/client.hpp"
#include "jsonrpccxx/server.hpp"

#include <networks/network.h>
#include <libdevcore/logger.h>
#include <libdevcore/timer.h>
#include <libp2p/net_errors.h>
#include <libp2p/workflow_node.h>
#include <libcoind/data.h>
#include <libcoind/types.h>

#include <nlohmann/json.hpp>
#include <boost/asio.hpp>
#include <boost/beast.hpp>
namespace io = boost::asio;
namespace beast = boost::beast;
namespace http = beast::http;
using tcp = io::ip::tcp;

class CoindRPC : public jsonrpccxx::IClientConnector, public WorkflowNode
{
	const std::string id = "curltest";

public:
	struct rpc_auth_data
	{
		const char *ip;
    	const char *port;
		char *authorization;
		char *host;

		rpc_auth_data() = default;
		rpc_auth_data(const char *_ip, const char *_port) : ip(_ip), port(_port)
		{
			
		}
	};

protected:
    io::io_context* context;
	c2pool::Timer reconnect_timer;

	rpc_auth_data auth;
    jsonrpccxx::JsonRpcClient client;

    coind::ParentNetwork* parent_net;
	tcp::resolver resolver;
	beast::tcp_stream stream;
    http::request<http::string_body> http_request;

	void run_node() override
    {
		LOG_INFO << "CoindRPC running...";
		try_connect();
    }

	void stop_node() override
	{
		LOG_INFO << "CoindRPC stopping...!";
		beast::error_code ec;
		reconnect_timer.stop();
		stream.socket().shutdown(tcp::socket::shutdown_both, ec);
		stream.close();
	}

	void disconnect_notify() override
	{
		LOG_INFO << "...CoindRPC stopped!";
	}

public:
	void try_connect()
	{
		auto const results = resolver.resolve(auth.ip, auth.port);
		boost::asio::ip::tcp::endpoint endpoint = *results; //(boost::asio::ip::make_address(auth.ip), auth.port);

        stream.async_connect(endpoint, 
			[&, PROCESS_DUPLICATE](boost::system::error_code ec)
			{
				WORKFLOW_PROCESS();

				if (ec)
				{
					if (ec == boost::system::errc::operation_canceled)
						return;
					
					LOG_ERROR << "CoindRPC error when try connect: [" << ec.message() << "].";
				} else 
				{
					try
					{
						if (check())
						{
							WORKFLOW_PROCESS_FINISH();
							connected();
							LOG_INFO << "...CoindRPC connected!";
							return;
						}
					}
					catch(const libp2p::node_exception& e)
					{
						LOG_ERROR << "Error when try check CoindRPC: " << e.what();
					}
				}
				
				LOG_INFO << "Retry after 15 seconds...";
				reconnect_timer.start(15, [this, PROCESS_DUPLICATE] { WORKFLOW_PROCESS(); try_connect(); });
				stream.close();
			}
		);
	}

public:
	// login = "login:password"
    CoindRPC(io::io_context* ctx, coind::ParentNetwork* _parent_net, rpc_auth_data _auth, const char* login) 
		: context(ctx), reconnect_timer(context), 
			resolver(*context), stream(*context), 
			client(*this, jsonrpccxx::version::v2), 
			parent_net(_parent_net), auth(_auth)
    {
		http_request = {http::verb::post, "/", 11};

        auth.host = new char[strlen(auth.ip) + strlen(auth.port) + 2];
        sprintf(auth.host, "%s:%s", auth.ip, auth.port);
        http_request.set(http::field::host, auth.host);

        http_request.set(http::field::user_agent, BOOST_BEAST_VERSION_STRING);
        http_request.set(http::field::content_type, "application/json");

        char *encoded_login = new char[32];
        boost::beast::detail::base64::encode(encoded_login, login, strlen(login));
        auth.authorization = new char[6 + strlen(encoded_login) + 1];
        sprintf(auth.authorization, "Basic %s", encoded_login);
        http_request.set(http::field::authorization, auth.authorization);
        delete[] encoded_login;
    }

    ~CoindRPC()
	{
		beast::error_code ec;
		stream.socket().shutdown(tcp::socket::shutdown_both, ec);
		if (ec)
		{
			//TODO:
		}

		delete[] auth.host;
		delete[] auth.authorization;
	}

    std::string Send(const std::string &request) override 
	{
		http_request.body() = request;
		http_request.prepare_payload();
		try
		{
			http::write(stream, http_request);	
		}
		catch(const std::exception& e)
		{
			throw libp2p::node_exception("error when try to send message in CoindRPC -> " + std::string(e.what()), this);
		}

		beast::flat_buffer buffer;
		boost::beast::http::response<boost::beast::http::dynamic_body> response;

		try
        {
        	boost::beast::http::read(stream, buffer, response);
        }
        catch (const std::exception& ex)
        {
        	throw libp2p::node_exception("error when try to read response -> " + std::string(ex.what()), this);
        }

		std::string json_result = boost::beast::buffers_to_string(response.body().data());
    	LOG_DEBUG_COIND_RPC << "json_result: " << json_result;

		return json_result;
	}

	// From helper.py
	bool check();
	bool check_block_header(uint256 header);
	coind::getwork_result getwork(coind::TXIDCache &txidcache, const map<uint256, coind::data::tx_type> &known_txs = map<uint256, coind::data::tx_type>());
	// TODO: REWORK
	void submit_block(coind::data::types::BlockType &block, std::string mweb, /*bool use_getblocktemplate,*/ bool ignore_failure, bool segwit_activated);

	// Methods

	nlohmann::json CallAPIMethod(const std::string& method, const jsonrpccxx::positional_parameter& params = {})
	{
		try
		{
			return client.CallMethod<nlohmann::json>(id, method, params);
		}
		catch (const jsonrpccxx::JsonRpcException& ex)
		{
			throw libp2p::node_exception("CallAPIMethod error: " + std::string(ex.what()), this);
		}
	}

	nlohmann::json getnetworkinfo()
	{
		return CallAPIMethod("getnetworkinfo");
	}

	nlohmann::json getblockchaininfo()
	{
		return CallAPIMethod("getblockchaininfo");
	}

	nlohmann::json getmininginfo()
	{
		return CallAPIMethod("getmininginfo");
	}

	// verbose: true -- json result, false -- hex-encode result;
	nlohmann::json getblockheader(uint256 header, bool verbose = true)
	{
		return CallAPIMethod("getblockheader", {header, verbose});
	}

	// verbosity: 0 for hex-encoded data, 1 for a json object, and 2 for json object with transaction data
	nlohmann::json getblock(uint256 blockhash, int verbosity = 1)
	{
		return CallAPIMethod("getblock", {blockhash, verbosity});
	}

	nlohmann::json getblocktemplate(std::vector<string> rules)
	{
		nlohmann::json j = nlohmann::json::object({{"rules", rules}});
		return CallAPIMethod("getblocktemplate", {j});
	}
};