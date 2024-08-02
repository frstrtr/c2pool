#include "rpc.hpp"

#include <core/log.hpp>
namespace ltc
{

namespace coin
{
    
nlohmann::json RPCNode::CallAPIMethod(const std::string& method, const jsonrpccxx::positional_parameter& params)
{
	try
	{
		return m_client.CallMethod<nlohmann::json>(ID, method, params);
	}
	catch (const jsonrpccxx::JsonRpcException& ex)
	{
        // TODO:
		// throw libp2p::node_exception("CallAPIMethod error: " + std::string(ex.what()), this);
	}
}

bool RPCNode::check()
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
        LOG_WARNING << "RPCNode::check() exception: " << ex.what();
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

bool RPCNode::check_blockheader(uint256 header)
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

// RPC Methods

nlohmann::json RPCNode::getblocktemplate(std::vector<std::string> rules)
{
	nlohmann::json j = nlohmann::json::object({{"rules", rules}});
	return CallAPIMethod("getblocktemplate", {j});
}

nlohmann::json RPCNode::getnetworkinfo()
{
	return CallAPIMethod("getnetworkinfo");
}

nlohmann::json RPCNode::getblockchaininfo()
{
	return CallAPIMethod("getblockchaininfo");
}

nlohmann::json RPCNode::getmininginfo()
{
	return CallAPIMethod("getmininginfo");
}

// verbose: true -- json result, false -- hex-encode result;
nlohmann::json RPCNode::getblockheader(uint256 header, bool verbose)
{
	return CallAPIMethod("getblockheader", {header, verbose});
}

// verbosity: 0 for hex-encoded data, 1 for a json object, and 2 for json object with transaction data
nlohmann::json RPCNode::getblock(uint256 blockhash, int verbosity)
{
	return CallAPIMethod("getblock", {blockhash, verbosity});
}

} // namespace coin


} // namespace ltc