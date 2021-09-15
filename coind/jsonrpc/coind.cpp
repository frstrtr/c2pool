#include "coind.h"
#include "results.h"
using namespace coind::jsonrpc::data;

#include "univalue.h"

#include <iostream>
#include <set>
#include <string>
using std::set, std::string;

namespace coind::jsonrpc
{

    bool Coind::check()
    {
        if (!net->jsonrpc_check(shared_from_this()))
        {
            std::cout << "Check failed! Make sure that you're connected to the right bitcoind with --bitcoind-rpc-port, and that it has finished syncing!" << std::endl;
            //TODO LOG: Check failed! Make sure that you're connected to the right bitcoind with --bitcoind-rpc-port, and that it has finished syncing!
            return false;
        }

        bool version_check_result = net->version_check(GetNetworkInfo()["version"].get_int());
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

    getwork_result Coind::getwork(bool use_getblocktemplate)
    {
        UniValue work;
        UniValue getblocktemplate_result;
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

        int check_error_res = check_error(getblocktemplate_result);
        if (!check_error_res)
        {
            if (check_error_res == coind_error_codes::MethodNotFound)
            {
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
        vector<UniValue> packed_transactions = work["transactions"].getValues();
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

        getwork_result result(work, packed_transactions);
        return result;
    }
}