#include "coindrpc.h"

bool CoindRPC::check()
{
	if (!parent_net->jsonrpc_check())
	{
		LOG_ERROR << "Check failed! Make sure that you're connected to the right bitcoind with --bitcoind-rpc-port, and that it has finished syncing!" << std::endl;
		return false;
	}

	bool version_check_result = parent_net->version_check(getnetworkinfo()["version"].get<int>());
	if (!version_check_result)
	{
		LOG_ERROR << "Coind daemon too old! Upgrade!";
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

bool CoindRPC::check_block_header(uint256 header)
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

coind::getwork_result CoindRPC::getwork(coind::TXIDCache &txidcache, const map<uint256, coind::data::tx_type> &known_txs)
{
    time_t start = c2pool::dev::timestamp();
    auto work = getblocktemplate({"segwit", "mweb"}); // mweb -- for ltc
    time_t end = c2pool::dev::timestamp();
    //packed_tx
	if (!txidcache.is_started())
	    txidcache.start();

	vector<uint256> txhashes;
	vector<coind::data::tx_type> unpacked_transactions;
    for (auto& packed_tx : work["transactions"])
    {
        PackStream ps_tx;

        uint256 txid;
		std::string x;

        if (packed_tx.contains("data"))
            x = packed_tx["data"].get<std::string>();
        else
            x = packed_tx.get<std::string>();

        if (txidcache.exist(x))
        {
            txid = txidcache[x];
            txhashes.push_back(txid);
        } else 
        {
            ps_tx = PackStream(ParseHex(x));
            txid = coind::data::hash256(ps_tx, true);
			txidcache.add(x, txid);
			txhashes.push_back(txid);
        }


        coind::data::tx_type unpacked_tx;
        if (known_txs.count(txid))
        {
            unpacked_tx = known_txs.at(txid);
        } else
        {
            if (ps_tx.isNull())
                ps_tx = PackStream(ParseHex(x));
            unpacked_tx = unpack<coind::data::stream::TransactionType_stream>(ps_tx);
        }
        unpacked_transactions.push_back(unpacked_tx);
    }

    if ((c2pool::dev::timestamp() - txidcache.time()) > 1800)
    {
        map<string, uint256> keepers;
        for (int i = 0; i < txhashes.size(); i++)
        {
            std::string x;
            if (work["transactions"].contains("data"))
                x = work["transactions"].at(i);
            else
                x = work["transactions"].get<std::string>();

            uint256 txid = txhashes[i];
            keepers[x] = txid;
        }
        txidcache.clear();
        txidcache.add(keepers);
    }

    if (!work.contains("height"))
    {
        uint256 previous_block_hash = work["previousblockhash"].get<uint256>();
        work["height"] = getblock(previous_block_hash)["height"].get<int>() + 1;
    }

    return coind::getwork_result{work, unpacked_transactions, txhashes, end - start};
}

// p2pool: submit_block_rpc
// TODO: REWORK
void CoindRPC::submit_block(coind::data::types::BlockType &block, std::string mweb, /*bool use_getblocktemplate,*/ bool ignore_failure, bool segwit_activated)
{
    //TODO: @deferral.retry('Error submitting block: (will retry)', 10, 10)

    //TODO: TO OTHER METHOD:
//    segwit_rules = set(['!segwit', 'segwit'])
//    segwit_activated = len(segwit_rules - set(bitcoind_work.value['rules'])) < len(segwit_rules)

    nlohmann::json res;
    bool success = true;
//    if (use_getblocktemplate) ALWAYS TRUE
    if (true)
    {
        //TODO: yield request

        PackStream packed_block;
        if (segwit_activated)
        {
            packed_block = pack_to_stream<coind::data::stream::BlockType_stream>(block);
        } else 
        {
            // TODO: stripped block type?
//            packed_block = pack_to_stream<coind::data::stream::StrippedBlockType_stream>(coind::data::types::StrippedBlockType(block.header, block.txs));

            packed_block = pack_to_stream<coind::data::stream::BlockType_stream>(block);
        }

        res = client.CallMethod<nlohmann::json>(id, "submitblock", {HexStr(packed_block.data) + mweb});
        success = res.is_null();
    } else
    {
        //TODO: ?
        throw std::runtime_error("c2pool without getmemorypool");
        res = client.CallMethod<nlohmann::json>(id, "getmemorypool");
        success = res.is_null();
    }

    auto block_header_stream = pack_to_stream<coind::data::stream::BlockHeaderType_stream>(block.header);
    auto success_expected = parent_net->POW_FUNC(block_header_stream) <= FloatingInteger(block.header.bits).target();

    if ((!success && success_expected && !ignore_failure) || (success && !success_expected))
        LOG_ERROR << "Block submittal result: " << success << "(" << res.dump() << ") Expected: " << success_expected;
}