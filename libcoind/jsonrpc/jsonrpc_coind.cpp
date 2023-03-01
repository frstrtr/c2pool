#include "jsonrpc_coind.h"

#include <set>
#include <iostream>
using std::set;

UniValue coind::JSONRPC_Coind::_request(const char *method_name, std::shared_ptr<coind::jsonrpc::data::TemplateRequest> req_params)
{
	char* params;
	size_t params_len;
	if (req_params)
	{
		params_len = req_params->get_params().length();
		params = new char[params_len+1];
		strcpy(params, req_params->get_params().c_str());
	} else
	{
		params_len = 2;
		params = new char[params_len + 1];
		strcpy(params, "[]");
	}

	char* request_body = new char[strlen(req_format) + strlen(method_name) + params_len + 1];
	sprintf(request_body, req_format, method_name, params);
	req.body() = request_body;
	req.prepare_payload();

	http::write(stream, req);

	beast::flat_buffer buffer;
	boost::beast::http::response<boost::beast::http::dynamic_body> response;
	boost::beast::http::read(stream, buffer, response);

	std::string json_result = boost::beast::buffers_to_string(response.body().data());
    LOG_DEBUG_COIND_JSONRPC << "json_result: " << json_result;
	UniValue result(UniValue::VOBJ);
	result.read(json_result);

	delete[] params;
	delete[] request_body;
	return result;
}

UniValue coind::JSONRPC_Coind::request(const char *method_name, std::shared_ptr<coind::jsonrpc::data::TemplateRequest> req_params)
{
    LOG_DEBUG_COIND_JSONRPC << "JsonRPC COIND request: " << method_name;
	auto result =  _request(method_name, req_params);
	if (!result["error"].isNull())
	{
		LOG_ERROR << "Error in request JSONRPC_COIND[" << parent_net->net_name << "]: " << result["error"].get_str();
	}
	return result["result"].get_obj();
}

UniValue coind::JSONRPC_Coind::request_with_error(const char *method_name, std::shared_ptr<coind::jsonrpc::data::TemplateRequest> req_params)
{
	return _request(method_name, req_params);
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
		LOG_ERROR << "Coin daemon too old! Upgrade!";
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

bool coind::JSONRPC_Coind::check_block_header(uint256 header)
{
	std::shared_ptr<jsonrpc::data::GetBlockHeaderRequest> req = std::make_shared<jsonrpc::data::GetBlockHeaderRequest>(header);
	UniValue result = getblockheader(req, true);
	if (result["error"].isNull())
	{
		return true;
	}
	else
	{
		return false;
	}
}

coind::getwork_result coind::JSONRPC_Coind::getwork(TXIDCache &txidcache, const map<uint256, coind::data::tx_type> &known_txs)
{
	UniValue work;
	UniValue getblocktemplate_result;

	time_t start;
	time_t end;

	start = c2pool::dev::timestamp();

	auto req = std::make_shared<GetBlockTemplateRequest>();
	req->mode = "template";
	req->rules.push_back("segwit");
	getblocktemplate_result = getblocktemplate(req, true);

	end = c2pool::dev::timestamp();

	auto [ec, ec_msg] = check_error(getblocktemplate_result);
	if (ec)
	{
		LOG_ERROR << "Error code: " << ec << ", Error message: " << ec_msg;
		throw std::runtime_error(ec_msg); // TODO: Custom error for jsonrpc
	}
	work = getblocktemplate_result["result"].get_obj();

	//packed_tx
	if (!txidcache.is_started())
		txidcache.start();

	vector<UniValue> packed_transactions = work["transactions"].getValues();

	vector<uint256> txhashes;
	vector<coind::data::tx_type> unpacked_transactions;
	for (auto _x: packed_transactions)
	{
		PackStream packed;
		uint256 txid;
		string x;
		if (_x.exists("data"))
			x = _x["data"].get_str();
		else
			x = _x.get_str();

		if (txidcache.exist(x))
		{
			txid = txidcache[x];
			txhashes.push_back(txid);
		} else
		{
			packed = PackStream(ParseHex(x));
			txid = coind::data::hash256(packed, true);
			txidcache.add(x, txid);
			txhashes.push_back(txid);
		}
		//-------------

		coind::data::tx_type unpacked;
		if (known_txs.find(txid) != known_txs.end())
		{
			unpacked = known_txs.at(txid);
		} else
		{
			if (packed.isNull())
			{
				packed = PackStream(ParseHex(x));
			}
			coind::data::stream::TransactionType_stream _unpacked;
			packed >> _unpacked;
			unpacked = _unpacked.tx;
		}
		unpacked_transactions.push_back(unpacked);
	}

	if ((c2pool::dev::timestamp() - txidcache.time()) > 1800)
	{
		map<string, uint256> keepers;
		for (int i = 0; i < txhashes.size(); i++)
		{
			string x;
			if (packed_transactions[i].exists("data"))
				x = packed_transactions[i]["data"].get_str();
			else
				x = packed_transactions[i].get_str();

			uint256 txid = txhashes[i];
			keepers[x] = txid;
		}
		txidcache.clear();
		txidcache.add(keepers);
	}

	if (!work.exists("height"))
	{
		uint256 previous_block_hash;
		previous_block_hash.SetHex(work["previousblockhash"].get_str());
		auto getblock_req = std::make_shared<GetBlockRequest>(previous_block_hash);
		work.pushKV("height", getblock(getblock_req).get_int() + 1);
	}

	//TODO:
	// elif p2pool.DEBUG:
	// assert work['height'] == (yield bitcoind.rpc_getblock(work['previousblockhash']))['height'] + 1


	getwork_result result(work, unpacked_transactions, txhashes, end - start);
    return result;
}