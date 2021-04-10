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
    struct getwork_result{
        int version;
        uint256 previous_block;
        //vector<> transactions=unpacked_transactions,
        //vector<> transaction_hashes=txhashes,
        //vector<> transaction_fees=[x.get('fee', None) if isinstance(x, dict) else None for x in work['transactions']],
        long long subsidy;
        time_t time; //=work['time'] if 'time' in work else work['curtime'],
        uint256 bits; //=bitcoin_data.FloatingIntegerType().unpack(work['bits'].decode('hex')[::-1]) if isinstance(work['bits'], (str, unicode)) else bitcoin_data.FloatingInteger(work['bits']),
        uint256 coinbaseflags; //=work['coinbaseflags'].decode('hex') if 'coinbaseflags' in work else ''.join(x.decode('hex') for x in work['coinbaseaux'].itervalues()) if 'coinbaseaux' in work else '',
        int height; //=work['height'],
        vector<string> rules; //=work.get('rules', []),
        time_t last_update; //=time.time(),
        bool use_getblocktemplate; //=use_getblocktemplate,
        time_t latency; //=end - start,
    };
} // namespace coind::jsonrpc::data