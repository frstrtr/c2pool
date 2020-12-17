#include "jsonrpc-bitcoind/bitcoind.h"
#include "config.h"
#include "other.h"
#include "jsonrpc-bitcoind/requests.h"
#include "uint256.h"

#include <map>
#include <string>
#include <set>
#include <vector>

using namespace std;
using namespace c2pool::bitcoind::jsonrpc;
using c2pool::config::Network;

namespace bitcoind::helper
{
    void check(shared_prt<Bitcoind> bitcoind, shared_ptr<Network> net) //TODO: args?
    {
        if (!net->RPC_CHECK(bitcoind))
        { //TODO: add to Network RPC_CHECK
            LOG_ERROR << "Check failed! Make sure that you're connected to the right bitcoind with --bitcoind-rpc-port, and that it has finished syncing!";
            //TODO?: raise deferral.RetrySilentlyException()
        }

        bool version_check_result = net->VERSION_CHECK(bitcoind->getnetworkinfo.version); //TODO: create getnetworkinfo
        if (!version_check_result)
        {
            LOG_ERROR << "Coin daemon too old! Upgrade!";
            //TODO?: raise deferral.RetrySilentlyException()
        }

        auto blockchaininfo = bitcoind->GetBlockChainInfo();
        //TODO: check for supported softforks
        //TODO: unsupported_forks = getattr(net, 'SOFTFORKS_REQUIRED', set()) - softforks_supported

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
    }

    struct GetWorkResult
    {
        int version;
        uint256 previous_block;
        //TODO:  transactions=unpacked_transactions //bitcoin_data.tx_type.unpack(packed)
        vector<uint256> transaction_hashes;
        int transaction_fees;
        long long *subsidy;
        long long time;
        string bits;
        //TODO: coinbaseflags //coinbaseaux
        long long height;
        vector<string> rules;
        int last_update; //c2pool::time::timestamp();
        bool use_getblocktemplate;
        int latency;
    };

    GetWorkResult getwork(shared_ptr<Bitcoind> bitcoind, bool use_getblocktemplate = false /*TODO:, txidcache={}, known_txs={}*/)
    {
        auto start = c2pool::time::timestamp();

        auto work; //TODO: base type
        if (use_getblocktemplate)
        {
            GetBlockTemplateRequest *req = new GetBlockTemplateRequest();
            req->mode = new string("template");
            req->rules.push_back("segwit");
            work = bitcoind->GetBlockTemplate(req);
        }
        else
        {
            work = bitcoind->getmemorypool(); //TODO: create method;
        }

        auto end = c2pool::time::timestamp();
        //TODO: проверка на наличие GetBlockTemplate в bitcoind. except jsonrpc.Error_for_code(-32601): # Method not found {use_getblocktemplate = not use_getblocktemplate}

        if (txidcache.find("start") == txidcache.end())
        {
            txidcache["start"] = c2pool::time::timestamp();
        }

        auto t0 = c2pool::time::timestamp();

        /*TODO:
        for x in work['transactions']:
        x = x['data'] if isinstance(x, dict) else x
        packed = None
        if x in txidcache:
            cachehits += 1
            txid = (txidcache[x])
            txhashes.append(txid)
        else:
            cachemisses += 1
            packed = x.decode('hex')
            txid = bitcoin_data.hash256(packed)
            txidcache[x] = txid
            txhashes.append(txid)
        if txid in known_txs:
            knownhits += 1
            unpacked = known_txs[txid]
        else:
            knownmisses += 1
            if not packed:
                packed = x.decode('hex')
            unpacked = bitcoin_data.tx_type.unpack(packed)
        unpacked_transactions.append(unpacked)
        */
        for (auto tx : work.transactions)
        {
            x = tx.data;
        }

        /*TODO:
        if time.time() - txidcache['start'] > 30*60.:
        keepers = {(x['data'] if isinstance(x, dict) else x):txid for x, txid in zip(work['transactions'], txhashes)}
        txidcache.clear()
        txidcache.update(keepers)
        */
        // if (c2pool::time::timestamp() - txidcache["start"] > 30*60){

        // }

        //FOR? LEGACY?
        //     if 'height' not in work:
        //     work['height'] = (yield bitcoind.rpc_getblock(work['previousblockhash']))['height'] + 1
        // elif p2pool.DEBUG:
        //     assert work['height'] == (yield bitcoind.rpc_getblock(work['previousblockhash']))['height'] + 1

        auto t1 = c2pool::time::timestamp();
        //TODO LOG: if p2pool.BENCH: print "%8.3f ms for helper.py:getwork(). Cache: %i hits %i misses, %i known_tx %i unknown %i cached" % ((t1 - t0)*1000., cachehits, cachemisses, knownhits, knownmisses, len(txidcache))

        GetWorkResult result = {
            work.version,
            work.previousblock,
            txhashes,
            //transaction_fees INIT
            work.coinbasevalue,
            work.curtime,
            work.bits,
            work.height,
            work.rules,
            c2pool::time::timestamp(),
            use_getblocktemplate,
            end - start};
    }

    //todo: submit_block_p2p
    //todo: submit_block_rpc
    //todo: submit_block

    bool check_block_header(shared_ptr<Bitcoind> bitcoind, uint256 block_hash)
    {
        auto blockheader = bitcoind->GetBlockHeader(block_hash); //TODO: create GetBlockHeader
        if (blockheader) //pointer
        {
            return true;
        }
        else
        {
            return false;
        }
    }
} // namespace bitcoind::helper