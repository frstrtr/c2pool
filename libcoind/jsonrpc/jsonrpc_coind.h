#ifndef C2POOL_JSONRPC_COIND_H
#define C2POOL_JSONRPC_COIND_H

#include <nlohmann/json.hpp>
#include <boost/asio.hpp>
#include <boost/beast.hpp>
namespace io = boost::asio;
namespace beast = boost::beast;
namespace http = beast::http;
using tcp = io::ip::tcp;

#include <networks/network.h>
#include <libdevcore/logger.h>

#include "requests.h"
#include "txidcache.h"
#include "results.h"
#include <libcoind/data.h>
#include <libcoind/types.h>
using namespace coind::jsonrpc::data;

// rework for include/jsonrpccxx
namespace coind
{
	class JSONRPC_Coind
	{
	private:
		std::shared_ptr<io::io_context> context;
		std::shared_ptr<coind::ParentNetwork> parent_net;
		tcp::resolver resolver;
		beast::tcp_stream stream;

		// const char *req_format = R"({"jsonrpc": "2.0", "id":"curltest", "method": "%s", "params": %s })";
		http::request<http::string_body> http_request;

		char *authorization;
		char *host;
        const char *ip;
        const char *port;
	private:
        void reconnect()
        {
            auto const results = resolver.resolve(ip, port);

            boost::system::error_code ec;
            do
            {
                stream.connect(results, ec);
                if (ec)
                {
                    LOG_INFO << "JSONRPC_Coind error when try connect: [" << ec.message()
                             << "]. Retry after 15 seconds...";
                    this_thread::sleep_for(15s);
                }
            } while (ec);
        }

		inline nlohmann::json reque(std::string method_name, nlohmann::json params = nlohmann::json::array())
		{
			nlohmann::json req 
			{
				{"jsonrpc", "2.0"},
				{"id", "curltest"},
				{"method", method_name},
				{"params", params}
			};

			std::string request_body = req.dump();
			http_request.body() = request_body;
			http_request.prepare_payload();

			http::write(stream, http_request);

			beast::flat_buffer buffer;
			boost::beast::http::response<boost::beast::http::dynamic_body> response;
			while (true)
			{
				try
        		{
            		boost::beast::http::read(stream, buffer, response);
            		break;
        		}
        		catch (const std::exception& ex)
        		{
            		LOG_ERROR << "JSONRPC disconnected for reason: _request." << ex.what();
            		reconnect();
        		}
//        		catch (...)
//        		{
//            		LOG_ERROR << "JSONRPC::_request error: DISCONNECTED2";
//            		reconnect();
//        		}
			}

			std::string json_result = boost::beast::buffers_to_string(response.body().data());
    		LOG_DEBUG_COIND_JSONRPC << "json_result: " << json_result;

			nlohmann::json result;
			result.parse(json_result);

			return result;
		}

		//TODO: template request params
		// UniValue _request(const char *method_name, std::shared_ptr<coind::jsonrpc::data::TemplateRequest> req_param = nullptr);

		// UniValue request(const char *method_name, std::shared_ptr<coind::jsonrpc::data::TemplateRequest> req_param = nullptr, bool ignore_result = false);

		// UniValue request_with_error(const char* method_name, std::shared_ptr<coind::jsonrpc::data::TemplateRequest> req_param = nullptr);

		enum coind_error_codes
		{
			MethodNotFound = -32601
		};

		//https://github.com/bitcoin/bitcoin/blob/master/src/rpc/protocol.h
		//0 = OK!
		std::tuple<int, std::string> check_error(UniValue result)
		{
			if (!result.exists("error") || result["error"].empty())
			{
				return std::make_tuple(0, "");
			}

			auto error_obj = result["error"].get_obj();
			int ec = error_obj["code"].get_int();
			string ec_msg = error_obj["message"].get_str();

			return std::make_tuple(ec, ec_msg);
		}

	public:

		// login = "login:password"
		JSONRPC_Coind(std::shared_ptr<io::io_context> _context, shared_ptr<coind::ParentNetwork> _parent_net,
					  const char *_ip, const char *_port, const char *login) : context(_context), parent_net(_parent_net),
																			 resolver(*_context), stream(*_context),
                                                                             ip(_ip), port(_port)
		{
            //Request
            req = {http::verb::post, "/", 11};

            host = new char[strlen(ip) + strlen(port) + 2];
            sprintf(host, "%s:%s", ip, port);
            req.set(http::field::host, host);

            req.set(http::field::user_agent, BOOST_BEAST_VERSION_STRING);
            req.set(http::field::content_type, "application/json");

            char *encoded_login = new char[32];
            boost::beast::detail::base64::encode(encoded_login, login, strlen(login));
            authorization = new char[6 + strlen(encoded_login) + 1];
            sprintf(authorization, "Basic %s", encoded_login);
            req.set(http::field::authorization, authorization);
            delete[] encoded_login;

			reconnect();
		}

		~JSONRPC_Coind()
		{
			beast::error_code ec;
			stream.socket().shutdown(tcp::socket::shutdown_both, ec);
			if (ec)
			{
				//TODO:
			}

			delete[] host;
			delete[] authorization;
		}

	public:
		// From p2pool.helper.py:

		bool check();

		bool check_block_header(uint256 header);

		getwork_result getwork(TXIDCache &txidcache, const map<uint256, coind::data::tx_type> &known_txs = map<uint256, coind::data::tx_type>());

        void submit_block(coind::data::types::BlockType &block, std::string mweb, /*bool use_getblocktemplate,*/ bool ignore_failure, bool segwit_activated);

	public:
		UniValue getblockchaininfo(bool full = false)
		{
			if (full)
				return request_with_error("getblockchaininfo");
			else
				return request("getblockchaininfo");
		}

		UniValue getmininginfo()
		{
			return request("getmininginfo");
		}

		UniValue getnetworkinfo()
		{
			return request("getnetworkinfo");
		}

		UniValue getblock(std::shared_ptr<GetBlockRequest> _req)
		{
			return request("getblock", _req);
		}

		UniValue getblockheader(std::shared_ptr<GetBlockHeaderRequest> _req, bool full = false)
		{
			if (full)
				return request_with_error("getblockheader", _req);
			else
				return request("getblockheader", _req);
		}

		//https://bitcoincore.org/en/doc/0.18.0/rpc/mining/getblocktemplate/
		UniValue getblocktemplate(std::shared_ptr<GetBlockTemplateRequest> _req, bool full = false)
		{
			if (full)
				return request_with_error("getblocktemplate", _req);
			else
				return request("getblocktemplate", _req);
		}
	};
} // namespace coind

#endif // C2POOL_JSONRPC_COIND_H
