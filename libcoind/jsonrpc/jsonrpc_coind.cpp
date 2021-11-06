#include "jsonrpc_coind.h"

#include <set>
#include <iostream>
using std::set;

UniValue coind::JSONRPC_Coind::_request(const char *method_name)
{
	char* request_body = new char[strlen(req_format) + strlen(method_name) + 2 + 1];
	sprintf(request_body, req_format, method_name, "[]");
	req.body() = request_body;
	req.prepare_payload();
	http::write(stream, req);

	beast::flat_buffer buffer;
	boost::beast::http::response<boost::beast::http::dynamic_body> response;
	boost::beast::http::read(stream, buffer, response);

	std::string json_result = boost::beast::buffers_to_string(response.body().data());
	std::cout << "Request result: " << json_result << std::endl;
	UniValue result(UniValue::VOBJ);
	result.read(json_result);
	std::cout << "After parsing: " << result.write()  << std::endl;
	return result;
}

UniValue coind::JSONRPC_Coind::request(const char *method_name)
{
	auto result =  _request(method_name);
	if (!result["error"].isNull())
	{
		LOG_ERROR << "Error in request JSONRPC_COIND[" << parent_net->net_name << "]: " << result["error"].get_str();
	}
	std::cout << "AFTER ERROR" << std::endl;
	std::cout << result.write() << std::endl;
	std::cout << "result: " << result["result"].type() << std::endl;
	return result["result"].get_obj();
}

UniValue coind::JSONRPC_Coind::request_with_error(const char *method_name)
{
	return _request(method_name);
}

bool coind::JSONRPC_Coind::check()
{
	if (!parent_net->jsonrpc_check())
	{
		LOG_ERROR << "Check failed! Make sure that you're connected to the right bitcoind with --bitcoind-rpc-port, and that it has finished syncing!" << std::endl;
		return false;
	}

	bool version_check_result = parent_net->version_check(getnetworkinfo()["version"].get_int());
	if (!version_check_result)
	{
		std::cout << "Coin daemon too old! Upgrade!" << std::endl;
		return false;
	}

	auto _blockchaininfo_full = getblockchaininfo();
	set<string> softforsk_supported;
	//TODO: check softforks:
	if (_blockchaininfo_full["error"].isNull())
	{
		// try:
		//     softforks_supported = set(item['id'] for item in blockchaininfo.get('softforks', [])) # not working with 0.19.0.1
		// except TypeError:
		//     softforks_supported = set(item for item in blockchaininfo.get('softforks', [])) # fix for https://github.com/jtoomim/p2pool/issues/38
		// try:
		//     softforks_supported |= set(item['id'] for item in blockchaininfo.get('bip9_softforks', []))
		// except TypeError: # https://github.com/bitcoin/bitcoin/pull/7863
		//     softforks_supported |= set(item for item in blockchaininfo.get('bip9_softforks', []))
	}
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

//TODO:
//bool coind::JSONRPC_Coind::check_block_header(uint256 header)
//{
//	GetBlockHeaderRequest *req = new GetBlockHeaderRequest(blockhash);
//	UniValue result = getblockheader(req, true);
//	if (result["error"].isNull())
//	{
//		return true;
//	}
//	else
//	{
//		return false;
//	}
//}
