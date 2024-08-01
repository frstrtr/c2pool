#include "rpc.hpp"

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