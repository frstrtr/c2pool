#pragma once

#include <btclibs/uint256.h>
#include <univalue.h>

#include <string>
#include <vector>
#include <map>

//TODO: for debug
#include <iostream>
using namespace std;

namespace coind::jsonrpc::data
{
    struct getwork_result
    {
        int version;
        uint256 previous_block;
        //vector<> transactions=unpacked_transactions,
        //vector<> transaction_hashes=txhashes,
        //vector<> transaction_fees=[x.get('fee', None) if isinstance(x, dict) else None for x in work['transactions']],
        long long subsidy;
        time_t time;               //=work['time'] if 'time' in work else work['curtime'],
        uint256 bits;              //=bitcoin_data.FloatingIntegerType().unpack(work['bits'].decode('hex')[::-1]) if isinstance(work['bits'], (str, unicode)) else bitcoin_data.FloatingInteger(work['bits']),
        uint256 coinbaseflags;     //=work['coinbaseflags'].decode('hex') if 'coinbaseflags' in work else ''.join(x.decode('hex') for x in work['coinbaseaux'].itervalues()) if 'coinbaseaux' in work else '',
        int height;                //=work['height'],
        vector<string> rules;      //=work.get('rules', []),
        time_t last_update;        //=time.time(),
        bool use_getblocktemplate; //=use_getblocktemplate,
        time_t latency;            //=end - start,

        getwork_result(){}

        getwork_result(UniValue work, vector<UniValue> packed_txs)
        {
            /*
                version=work['version'],
                previous_block=int(work['previousblockhash'], 16),
                transactions=map(bitcoin_data.tx_type.unpack, packed_transactions),
                transaction_hashes=map(bitcoin_data.hash256, packed_transactions),
                transaction_fees=[x.get('fee', None) if isinstance(x, dict) else None for x in work['transactions']],
                subsidy=work['coinbasevalue'],
                time=work['time'] if 'time' in work else work['curtime'],
                bits=bitcoin_data.FloatingIntegerType().unpack(work['bits'].decode('hex')[::-1]) if isinstance(work['bits'], (str, unicode)) else bitcoin_data.FloatingInteger(work['bits']),
                coinbaseflags=work['coinbaseflags'].decode('hex') if 'coinbaseflags' in work else ''.join(x.decode('hex') for x in work['coinbaseaux'].itervalues()) if 'coinbaseaux' in work else '',
                height=work['height'],
                last_update=time.time(),
                use_getblocktemplate=use_getblocktemplate,
                latency=end - start,
            */
            version = work["version"].get_int();
            previous_block.SetHex(work["previousblockhash"].get_str());
            
        }
    };
} // namespace coind::jsonrpc::data