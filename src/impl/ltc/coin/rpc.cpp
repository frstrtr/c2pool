#include "rpc.hpp"

#include <core/log.hpp>
namespace ltc
{

namespace coin
{

NodeRPC::NodeRPC(io::io_context* context, RPCAuthData auth, const char* login)
    : m_context(context), m_resolver(*context), m_stream(*context),
    m_client(*this, RPC_VER), m_auth(std::make_unique<RPCAuthData>(auth))
{
    m_http_request = {http::verb::post, "/", 11};

    m_auth->host = new char[strlen(m_auth->ip) + strlen(m_auth->port) + 2];
    sprintf(m_auth->host, "%s:%s", m_auth->ip, m_auth->port);
    m_http_request.set(http::field::host, m_auth->host);

    m_http_request.set(http::field::user_agent, BOOST_BEAST_VERSION_STRING);
    m_http_request.set(http::field::content_type, "application/json");

    char *encoded_login = new char[32];
    boost::beast::detail::base64::encode(encoded_login, login, strlen(login));
    m_auth->authorization = new char[6 + strlen(encoded_login) + 1];
    sprintf(m_auth->authorization, "Basic %s", encoded_login);
    m_http_request.set(http::field::authorization, m_auth->authorization);
    delete[] encoded_login;
}

NodeRPC::~NodeRPC()
{
    beast::error_code ec;
	m_stream.socket().shutdown(io::ip::tcp::socket::shutdown_both, ec);
	if (ec)
	{
		//TODO:
	}

	// move to RPCAuthData
	delete[] m_auth->host;
	delete[] m_auth->authorization;
}


nlohmann::json NodeRPC::CallAPIMethod(const std::string& method, const jsonrpccxx::positional_parameter& params)
{
	try
	{
		return m_client.CallMethod<nlohmann::json>(ID, method, params);
	}
	catch (const jsonrpccxx::JsonRpcException& ex)
	{
		throw std::runtime_error("CallAPIMethod error: " + std::string(ex.what()));
        // TODO:
		// throw libp2p::node_exception("CallAPIMethod error: " + std::string(ex.what()), this);
	}
}

bool NodeRPC::check()
{
	bool has_block = check_blockheader(uint256S("12a765e31ffd4059bada1e25190f6e98c99d9714d334efa41a195a7e7e04bfe2"));
	bool is_main_chain = getblockchaininfo()["chain"].get<std::string>() == "main";

	if (!(has_block && is_main_chain))
	{
		LOG_ERROR << "Check failed! Make sure that you're connected to the right bitcoind with --bitcoind-rpc-port, and that it has finished syncing!" << std::endl;
		return false;
	}

	try
    {
		auto networkinfo = getnetworkinfo();
		bool version_check_result = (100400 <= networkinfo.get<int>());
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