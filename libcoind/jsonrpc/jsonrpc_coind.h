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

namespace coind
{
	class JSONRPC_Coind
	{
	private:
		std::shared_ptr<io::io_context> _context;
		shared_ptr<coind::ParentNetwork> _parent_net;
		tcp::resolver _resolver;
		beast::tcp_stream _stream;

		const char* req_format = "{\"jsonrpc\": \"2.0\", \"id\":\"curltest\", \"method\": \"%s\", \"params\": %s }";
		http::request<http::string_body> req;
	public:

		// login = "login:password"
		JSONRPC_Coind(std::shared_ptr<io::io_context> __context, shared_ptr<coind::ParentNetwork> parent_net, const char* ip, const char* port, const char* login) : _context(__context), _parent_net(parent_net), _resolver(*_context), stream(*_context)
		{
			//Request
			req = {http::verb::post, "/", 11};

			char* host = new char[strlen(ip) + strlen(port) + 2];
			sprintf(host, "%s:%s", ip, port);
			req.set(http::field::host, host);

			req.set(http::field::user_agent, BOOST_BEAST_VERSION_STRING);
			req.set(http::field::content_type, "application/json");

			char* encoded_login = new char[64];
			boost::beast::detail::base64::encode(encoded_login, login, strlen(login));
			char* authorization = new char[6 + strlen(encoded_login) + 1];
			sprintf(authorization, "Basic %s", encoded_login);
			req.set(http::field::authorization, authorization);

			// Connection
			auto const results = _resolver.resolve(ip, port);
			_stream.connect(results);

			delete[] host;
			delete[] encoded_login;
			delete[] authorization;
		}

		~JSONRPC_Coind(){
			beast::error_code ec;
			_stream.socket().shutdown(tcp::socket::shutdown_both, ec);
			if (ec){//
// Created by sl33n on 05.11.2021.
//
				//TODO:
			}
		}

		//TODO: template request params
		UniValue _request(const char* method_name);

		UniValue request(const char* method_name){
			auto result =  _request(method_name);

			if (!result["error"].isNull())
			{
				//LOG_ERROR << result["error"].get_str();
			}
			return result["result"].get_obj();
		}
	};

} // namespace coind

#endif // C2POOL_JSONRPC_COIND_H
