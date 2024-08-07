#include "rpc.hpp"

#include <core/log.hpp>
namespace ltc
{

namespace coin
{

NodeRPC::NodeRPC(io::io_context* context, bool testnet)
    : m_context(context), IS_TESTNET(testnet), m_resolver(*context), m_stream(*context), 
	  m_client(*this, RPC_VER)
{
}

void NodeRPC::connect(NetService address, std::string userpass)
{
	m_auth = std::make_unique<RPCAuthData>();
	m_http_request = {http::verb::post, "/", 11};

    m_auth->host = address.to_string();
    m_http_request.set(http::field::host, m_auth->host);

    m_http_request.set(http::field::user_agent, BOOST_BEAST_VERSION_STRING);
    m_http_request.set(http::field::content_type, "application/json");

	char *encoded_login2 = new char[32];
    boost::beast::detail::base64::encode(encoded_login2, userpass.c_str(), strlen(userpass.c_str()));
	m_auth->authorization = "Basic " + std::string(encoded_login2, strlen(encoded_login2));
    m_http_request.set(http::field::authorization, m_auth->authorization);
	delete[] encoded_login2;

    auto const results = m_resolver.resolve(address.address(), address.port_str());
	boost::asio::ip::tcp::endpoint endpoint = *results;

    m_stream.async_connect(endpoint, 
		[&](boost::system::error_code ec)
		{
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
						// connected();
						LOG_INFO << "...CoindRPC connected!";
						return;
					}
				}
				catch(const std::runtime_error& ec)
				{
					LOG_ERROR << "Error when try check CoindRPC: " << ec.what();
				}
				// }
				// catch(const libp2p::node_exception& e)
				// {
				// 	LOG_ERROR << "Error when try check CoindRPC: " << e.what();
				// }
			}
			
			LOG_INFO << "Retry after 15 seconds...";
			// reconnect_timer.start(15, [this, PROCESS_DUPLICATE] { WORKFLOW_PROCESS(); try_connect(); });
			m_stream.close();
		}
	);
}

NodeRPC::~NodeRPC()
{
    beast::error_code ec;
	m_stream.socket().shutdown(io::ip::tcp::socket::shutdown_both, ec);
	if (ec)
	{
		//TODO:
	}
}

std::string NodeRPC::Send(const std::string &request)
{
	//TODO:
	m_http_request.body() = request;
	m_http_request.prepare_payload();
	try
	{
		// LOG_DEBUG_COIND_RPC << m_http_request.body();
		http::write(m_stream, m_http_request);	
	}
	catch(const std::exception& e)
	{
		LOG_WARNING << "error when try to send message in CoindRPC -> " << e.what();
		// throw libp2p::node_exception("error when try to send message in CoindRPC -> " + std::string(), this);
	}

	beast::flat_buffer buffer;
	boost::beast::http::response<boost::beast::http::dynamic_body> response;

	try
    {
    	boost::beast::http::read(m_stream, buffer, response);
    }
    catch (const std::exception& ex)
    {
		LOG_WARNING << "error when try to read response -> " << ex.what();
    	// throw libp2p::node_exception("error when try to read response -> " + std::string(ex.what()), this);
    }

	std::string json_result = boost::beast::buffers_to_string(response.body().data());
    LOG_DEBUG_COIND_RPC << "json_result: " << json_result;

	return json_result;
	// return std::string("");
}

nlohmann::json NodeRPC::CallAPIMethod(const std::string& method, const jsonrpccxx::positional_parameter& params)
{
	return m_client.CallMethod<nlohmann::json>(ID, method, params);
}

bool NodeRPC::check()
{
	bool has_block = check_blockheader(uint256S("12a765e31ffd4059bada1e25190f6e98c99d9714d334efa41a195a7e7e04bfe2"));
	bool is_main_chain = getblockchaininfo()["chain"].get<std::string>() == "main";

	if (is_main_chain && !has_block)
	{
		LOG_ERROR << "Check failed! Make sure that you're connected to the right bitcoind with --bitcoind-rpc-port, and that it has finished syncing!" << std::endl;
		return false;
	}

	try
    {
		auto networkinfo = getnetworkinfo();
		bool version_check_result = (100400 <= networkinfo["version"].get<int>());
		if (!version_check_result)
		{
			LOG_ERROR << "Coin daemon too old! Upgrade!";
			return false;
		}
	} catch (const jsonrpccxx::JsonRpcException& ex)
    {
        LOG_WARNING << "NodeRPC::check() exception: " << ex.what();
		return false;
    }

    try 
    {
	    auto blockchaininfo = getblockchaininfo();
    } catch (const jsonrpccxx::JsonRpcException& ex)
    {
        return false;
    }

	// set<string> softforsk_supported;
	//TODO: check softforks, move to try-catch upper:
	// if (blockchaininfo["error"].isNull()) 
	// {
	// 	// try:
	// 	//     softforks_supported = set(item['id'] for item in blockchaininfo.get('softforks', [])) # not working with 0.19.0.1
	// 	// except TypeError:
	// 	//     softforks_supported = set(item for item in blockchaininfo.get('softforks', [])) # fix for https://github.com/jtoomim/p2pool/issues/38
	// 	// try:
	// 	//     softforks_supported |= set(item['id'] for item in blockchaininfo.get('bip9_softforks', []))
	// 	// except TypeError: # https://github.com/bitcoin/bitcoin/pull/7863
	// 	//     softforks_supported |= set(item for item in blockchaininfo.get('bip9_softforks', []))
	// }
	// unsupported_forks = getattr(net, 'SOFTFORKS_REQUIRED', set()) - softforks_supported

	/*
	if unsupported_forks:
	print "You are running a coin daemon that does not support all of the "
	print "forking features that have been activated on this blockchain."
	print "Consequently, your node may mine invalid blocks or may mine blocks that"
	print "are not part of the Nakamoto consensus blockchain.\n"
	print "Missing fork features:", ', '.join(unsupported_forks)
	if not args.allow_obsolete_bitcoind:
		print "\nIf you know what you're doing, this error may be overridden by running p2pool"
		print "with the '--allow-obsolete-bitcoind' command-line option.\n\n\n"
		raise deferral.RetrySilentlyException()
	*/

	return true;
}

bool NodeRPC::check_blockheader(uint256 header)
{
    try 
    {
		getblockheader(header);
        return true;
    } catch (const jsonrpccxx::JsonRpcException& ex) 
    {
        return false;
    }
}

void NodeRPC::submit_block(BlockType& block)
{
	
}

// RPC Methods

nlohmann::json NodeRPC::getblocktemplate(std::vector<std::string> rules)
{
	nlohmann::json j = nlohmann::json::object({{"rules", rules}});
	return CallAPIMethod("getblocktemplate", {j});
}

nlohmann::json NodeRPC::getnetworkinfo()
{
	return CallAPIMethod("getnetworkinfo");
}

nlohmann::json NodeRPC::getblockchaininfo()
{
	return CallAPIMethod("getblockchaininfo");
}

nlohmann::json NodeRPC::getmininginfo()
{
	return CallAPIMethod("getmininginfo");
}

// verbose: true -- json result, false -- hex-encode result;
nlohmann::json NodeRPC::getblockheader(uint256 header, bool verbose)
{
	return CallAPIMethod("getblockheader", {header, verbose});
}

// verbosity: 0 for hex-encoded data, 1 for a json object, and 2 for json object with transaction data
nlohmann::json NodeRPC::getblock(uint256 blockhash, int verbosity)
{
	return CallAPIMethod("getblock", {blockhash, verbosity});
}

} // namespace coin


} // namespace ltc