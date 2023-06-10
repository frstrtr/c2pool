#ifndef C2POOL_JSONRPC_COIND_H
#define C2POOL_JSONRPC_COIND_H

#include <univalue.h>
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

namespace coind
{
	class JSONRPC_Coind
	{
	private:
		std::shared_ptr<io::io_context> context;
		shared_ptr<coind::ParentNetwork> parent_net;
		tcp::resolver resolver;
		beast::tcp_stream stream;

		const char *req_format = "{\"jsonrpc\": \"2.0\", \"id\":\"curltest\", \"method\": \"%s\", \"params\": %s }";
		http::request<http::string_body> req;

		char *authorization;
		char *host;

	private:
		//TODO: template request params
		UniValue _request(const char *method_name, std::shared_ptr<coind::jsonrpc::data::TemplateRequest> req_param = nullptr);

		UniValue request(const char *method_name, std::shared_ptr<coind::jsonrpc::data::TemplateRequest> req_param = nullptr);

		UniValue request_with_error(const char* method_name, std::shared_ptr<coind::jsonrpc::data::TemplateRequest> req_param = nullptr);

		enum coind_error_codes
		{
			MethodNotFound = -32601
		};

		//https://github.com/bitcoin/bitcoin/blob/master/src/rpc/protocol.h
		//0 = OK!
		std::tuple<int, std::string> check_error(UniValue result)
		{
			if (result.exists("error"))
			{
				if (result["error"].empty())
				{
					return std::make_tuple(0, "");
				}
			}
			else
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
					  const char *ip, const char *port, const char *login) : context(_context), parent_net(_parent_net),
																			 resolver(*_context), stream(*_context)
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

			// Connection
			auto const results = resolver.resolve(ip, port);
			stream.connect(results);

			delete[] encoded_login;
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

        void submit_block(coind::data::types::BlockType &block, /*bool use_getblocktemplate,*/ bool ignore_failure, bool segwit_activated);

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

		UniValue getblock(std::shared_ptr<GetBlockRequest> req)
		{
			return request("getblock", req);
		}

		UniValue getblockheader(std::shared_ptr<GetBlockHeaderRequest> req, bool full = false)
		{
			if (full)
				return request_with_error("getblockheader", req);
			else
				return request("getblockheader", req);
		}

		//https://bitcoincore.org/en/doc/0.18.0/rpc/mining/getblocktemplate/
		UniValue getblocktemplate(std::shared_ptr<GetBlockTemplateRequest> req, bool full = false)
		{
			if (full)
				return request_with_error("getblocktemplate", req);
			else
				return request("getblocktemplate", req);
		}

	};

} // namespace coind

#endif // C2POOL_JSONRPC_COIND_H
