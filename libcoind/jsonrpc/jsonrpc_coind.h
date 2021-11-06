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

	private:
		//TODO: template request params
		UniValue _request(const char *method_name);

		UniValue request(const char *method_name);

		UniValue request_with_error(const char* method_name);

	public:

		// login = "login:password"
		JSONRPC_Coind(std::shared_ptr<io::io_context> _context, shared_ptr<coind::ParentNetwork> _parent_net,
					  const char *ip, const char *port, const char *login) : context(_context), parent_net(_parent_net),
																			 resolver(*_context), stream(*_context)
		{
			//Request
			req = {http::verb::post, "/", 11};

			char *host = new char[strlen(ip) + strlen(port) + 2];
			sprintf(host, "%s:%s", ip, port);
			req.set(http::field::host, host);

			req.set(http::field::user_agent, BOOST_BEAST_VERSION_STRING);
			req.set(http::field::content_type, "application/json");

			char *encoded_login = new char[64];
			boost::beast::detail::base64::encode(encoded_login, login, strlen(login));
			char *authorization = new char[6 + strlen(encoded_login) + 1];
			sprintf(authorization, "Basic %s", encoded_login);
			req.set(http::field::authorization, authorization);

			// Connection
			auto const results = resolver.resolve(ip, port);
			stream.connect(results);

			delete[] host;
			delete[] encoded_login;
			delete[] authorization;
		}

		~JSONRPC_Coind()
		{
			beast::error_code ec;
			stream.socket().shutdown(tcp::socket::shutdown_both, ec);
			if (ec)
			{
				//TODO:
			}
		}

	public:
		// From p2pool.helper.py:

		bool check();

		//TODO: bool check_block_header(uint256 header);

		//TODO: getwork

	public:
		UniValue getblockchaininfo(bool full = false)
		{
			if (full)
				return request_with_error("getblockchaininfo");
			else
				return request("getblockchaininfo");
		}

		UniValue getnetworkinfo()
		{
			return request("getnetworkinfo");
		}

		/* TODO:
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

		UniValue getmemorypool(bool full = false)
		{
			if (full)
				return request_with_error("getmemorypool");
			else
				return request("getmemorypool");
		}
		*/
	};

} // namespace coind

#endif // C2POOL_JSONRPC_COIND_H
