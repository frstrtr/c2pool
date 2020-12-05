#ifndef JSONRPC_BITCOIND_RESULTS_H
#define JSONRPC_BITCOIND_RESULTS_H

#include <uint256.h>

#include <string>
#include <vector>
#include <map>

using std::string, std::vector, std::map;

namespace c2pool::bitcoind::data
{
    class Bip9SoftForkDescription{
        string status;
        char bit;
        long long startTime;
        long long start_time;
        long long timeout;
        int since;
    };

    class SoftForks{
        vector<SoftForks*> softforks; //TODO: ?
        map<string, Bip9SoftForkDescription> bip9_softforks;
    };
}

namespace c2pool::bitcoind::data
{
    class GetBlockChainInfoResult
    {
        string chain;
        int blocks;
        int headers;
        uint256 bestblockhash;
        double difficulty;
        unsigned long long mediantime;
        double verificationprogress;
        bool pruned;
        int pruneheight;
        SoftForks softforks; //TODO: name?
    };
} // namespace c2pool::bitcoind::data

#endif