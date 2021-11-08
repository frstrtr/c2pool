#include "coind.h"
#include "results.h"
using namespace coind::jsonrpc::data;

#include "univalue.h"
#include <libcoind/data.h>
#include <libdevcore/stream.h>
#include <btclibs/util/strencodings.h>
#include <libcoind/transaction.h>

#include <iostream>
#include <set>
#include <string>
#include <functional>
using std::set, std::string;

namespace coind::jsonrpc
{
    bool Coind::check()
    {
        if (!_parent_net->jsonrpc_check())
        {
            std::cout << "Check failed! Make sure that you're connected to the right bitcoind with --bitcoind-rpc-port, and that it has finished syncing!" << std::endl;
            //TODO LOG: Check failed! Make sure that you're connected to the right bitcoind with --bitcoind-rpc-port, and that it has finished syncing!
            return false;
        }

        bool version_check_result = _parent_net->version_check(GetNetworkInfo()["version"].get_int());
        if (!version_check_result)
        {
            std::cout << "Coin daemon too old! Upgrade!" << std::endl;
            return false;
        }

        auto _blockchaininfo_full = GetBlockChainInfo();
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

    bool Coind::check_block_header(uint256 blockhash)
    {
        GetBlockHeaderRequest *req = new GetBlockHeaderRequest(blockhash);
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

    getwork_result Coind::getwork(TXIDCache &txidcache, const map<uint256, coind::data::tx_type> &known_txs, bool use_getblocktemplate)
    {
        UniValue work;
        UniValue getblocktemplate_result;

        time_t start;
        time_t end;

        start = c2pool::dev::timestamp();
        if (use_getblocktemplate)
        {
            GetBlockTemplateRequest *req = new GetBlockTemplateRequest();
            req->mode = "template";
            req->rules.push_back("segwit");
            getblocktemplate_result = getblocktemplate(req, true);
        }
        else
        {
            getblocktemplate_result = getmemorypool(); //TODO
        }
        end = c2pool::dev::timestamp();

        int check_error_res = check_error(getblocktemplate_result);
        if (!check_error_res)
        {
            if (check_error_res == coind_error_codes::MethodNotFound)
            {
                start = c2pool::dev::timestamp();
                if (!use_getblocktemplate)
                {
                    GetBlockTemplateRequest *req = new GetBlockTemplateRequest();
                    req->mode = "template";
                    req->rules.push_back("segwit");
                    getblocktemplate_result = getblocktemplate(req, true);
                }
                else
                {
                    getblocktemplate_result = getmemorypool(); //TODO
                }
                end = c2pool::dev::timestamp();

                check_error_res = check_error(getblocktemplate_result);
                if (!check_error_res)
                {
                    //TODO: LOG ERROR 'Error: Bitcoin version too old! Upgrade to v0.5 or newer!'
                    //raise
                }
            }
        }
        work = getblocktemplate_result["result"].get_obj();

        //packed_tx
        if (!txidcache.is_started())
            txidcache.start();

        vector<UniValue> packed_transactions = work["transactions"].getValues();

        vector<uint256> txhashes;
        vector<coind::data::tx_type> unpacked_transactions;
        for (auto _x : packed_transactions)
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
            }
            else
            {
                packed = PackStream(ParseHex(x)); //TODO: TEST
                txid = coind::data::hash256(packed);
                txidcache.add(x, txid);
                txhashes.push_back(txid);
            }

            coind::data::tx_type unpacked;
            if (known_txs.find(txid) != known_txs.end())
            {
                unpacked = known_txs.at(txid);
            }
            else
            {
                if (packed.isNull())
                {
                    packed = PackStream(ParseHex(x)); //TODO: TEST
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
            GetBlockRequest *getblock_req = new GetBlockRequest(previous_block_hash);
            work.pushKV("height", GetBlock(getblock_req).get_int() + 1);
        }

        //TODO:
        // elif p2pool.DEBUG:
        // assert work['height'] == (yield bitcoind.rpc_getblock(work['previousblockhash']))['height'] + 1

        getwork_result result(work, unpacked_transactions, txhashes, end - start);
        return result;
    }
}