#ifndef JSONRPC_BITCOIND_RESULTS_H
#define JSONRPC_BITCOIND_RESULTS_H

#include "uint256.h"
#include "univalue.h"

#include <string>
#include <vector>
#include <map>

using std::string, std::vector, std::map;

namespace c2pool::bitcoind::jsonrpc::data
{
    class Bip9SoftForkDescription
    {
    public:
        string status;
        char bit;
        long long startTime;
        long long start_time;
        long long timeout;
        int since;

        Bip9SoftForkDescription &operator=(UniValue value)
        {
            status = value["status"].get_str();
            bit = value["bit"].get_str().c_str()[0];
            startTime = value["startTime"].get_int64();
            start_time = value["start_time"].get_int64();
            timeout = value["timeout"].get_int64();
            since = value["since"].get_int();
            return *this;
        }
    };

    class SoftForks
    {
    public:
        vector<SoftForks *> softforks; //TODO: ?
        map<string, Bip9SoftForkDescription> bip9_softforks;

        SoftForks &operator=(UniValue value)
        {
            //todo
            return *this;
        }
    };
} // namespace c2pool::bitcoind::data

namespace c2pool::bitcoind::jsonrpc::data
{
    class GetBlockChainInfoResult
    {
    public:
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

        GetBlockChainInfoResult &operator=(UniValue value)
        {
            chain = value["chain"].get_str();
            blocks = value["blocks"].get_int();
            headers = value["headers"].get_int();

            string bestblockhash_temp = value["bestblockhash"].get_str();
            bestblockhash.SetHex(bestblockhash_temp);

            difficulty = value["difficulty"].get_real();
            mediantime = value["mediantime"].get_int64();
            verificationprogress = value["verificationprogress"].get_real();
            pruned = value["pruned"].get_bool();
            pruneheight = value["pruneheight"].get_int();
            softforks = value["softforks"].get_obj();
            return *this;
        }
    };

    class NetworksResult
    {
    public:
        string name;
        bool limited;
        bool reachable;
        string proxy;
        bool proxy_randomize_credentials;

        NetworksResult &operator=(UniValue value)
        {
            name = value["name"].get_str();
            limited = value["limited"].get_bool();
            reachable = value["reachable"].get_bool();
            proxy = value["proxy"].get_str();
            proxy_randomize_credentials = value["proxy_randomize_credentials"].get_bool();

            return *this;
        }
    };

    class LocalAddressesResult
    {
    public:
        string address;
        short port;
        int score;

        LocalAddressesResult &operator=(UniValue value)
        {
            address = value["address"].get_str();
            port = value["port"].get_int();
            score = value["score"].get_int();
            return *this;
        }
    };

    class GetNetworkInfoResult
    {
    public:
        int version;
        string subversion;
        int protocolversion;
        string localservices;
        bool localrelay;
        long long timeoffset;
        int connectsions;
        bool networkactive;
        vector<NetworksResult> networks;
        double relayfee;
        double incrementalfee;
        vector<LocalAddressesResult> localaddresses;
        string warnings;

        GetNetworkInfoResult &operator=(UniValue value)
        {
            version = value["version"].get_int();
            subversion = value["subversion"].get_str();
            protocolversion = value["protocolversion"].get_int();
            localservices = value["localservices"].get_str();
            localrelay = value["localrelay"].get_bool();
            timeoffset = value["timeoffset"].get_int64();
            connectsions = value["connections"].get_int();
            networkactive = value["networkactive"].get_bool();
            for (auto obj : value["networks"].get_array().getValues())
            {
                NetworksResult tempNR;
                tempNR = obj.get_obj();
                networks.push_back(tempNR);
            }
            relayfee = value["relayfee"].get_real();
            incrementalfee = value["incrementalfee"].get_real();
            for (auto obj : value["localaddresses"].get_array().getValues())
            {
                LocalAddressesResult tempLAR;
                tempLAR = obj.get_obj();
                localaddresses.push_back(tempLAR);
            }
            warnings = value["warnings"].get_str();
            return *this;
        }
    };
} // namespace c2pool::bitcoind::data

//================================================================
//=========================Mining RPC=============================
//================================================================

//getblocktemplate
namespace c2pool::bitcoind::jsonrpc::data
{
    class GetBlockTemplateResultTx
    {
    public:
        string data;
        uint256 hash;
        string txid;
        vector<long long> depends;
        long long fee;
        long long sigops;
        long long wight;

        GetBlockTemplateResultTx &operator=(UniValue value)
        {
            data = value["data"].get_str();

            string hash_raw = value["hash"].get_str();
            hash.SetHex(hash_raw);

            txid = value["txid"].get_str();

            for (auto depend : value["depends"].get_array().getValues())
            {
                depends.push_back(depend.get_int64());
            }

            fee = value["fee"].get_int64();
            sigops = value["sigops"].get_int64();
            wight = value["wight"].get_int64();

            return *this;
        }
    };

    class GetBlockTemplateResultAux
    {
    public:
        string flags;

        GetBlockTemplateResultAux &operator=(UniValue value)
        {
            flags = value["flags"].get_str();

            return *this;
        }
    };

    class GetBlockTemplateResult
    {
    public:
        string bits;
        long long curtime;
        long long height;
        uint256 previousblockhash;
        long long sigoplimit;
        long long sizelimit;
        long long weightlimit;

        vector<GetBlockTemplateResultTx> transactions;

        int version;

        GetBlockTemplateResultAux *coinbaseaux;
        GetBlockTemplateResultTx *coinbasetxn;

        long long *coinbasevalue;
        string workid;

        // Witness commitment defined in BIP 0141.
        string default_witness_commitment;

        // Optional long polling from BIP 0022.
        string longpollid;
        string longpolluri;
        bool *submitold;

        // Basic pool extension from BIP 0023.
        string target;
        long long expires;

        // Mutations from BIP 0023.
        long long maxtime;
        long long mintime;
        vector<string> mutables; //json:mutable
        string noncerange;

        // Block proposal from BIP 0023.
        vector<string> capabilities;
        string reject_reason; //json: reject-reason

        GetBlockTemplateResult &operator=(UniValue value)
        {
            bits = value["bits"].get_str();
            curtime = value["curtime"].get_int64();
            height = value["height"].get_int64();

            string previousblockhash_raw = value["previousblockhash"].get_str();
            previousblockhash.SetHex(previousblockhash_raw);

            sigoplimit = value["sigoplimit"].get_int64();
            sizelimit = value["sizelimit"].get_int64();
            weightlimit = value["weightlimit"].get_int64();

            for (auto obj : value["transactions"].get_array().getValues())
            {
                GetBlockTemplateResultTx tx;
                tx = obj.get_obj();
                transactions.push_back(tx);
            }

            version = value["version"].get_int();

            *coinbaseaux = value["coinbaseaux"].get_obj();
            *coinbasetxn = value["coinbasetxn"].get_obj();

            *coinbasevalue = value["coinbasevalue"].get_int64(); //TODO:? nullptr

            workid = value["workid"].get_str();

            default_witness_commitment = value["default_witness_commitment"].get_str();

            longpollid = value["longpollid"].get_str();
            longpolluri = value["longpolluri"].get_str();
            *submitold = value["submitold"].get_bool(); //TODO: ? nullptr

            target = value["target"].get_str(); //TODO: uint256?
            expires = value["expires"].get_int64();

            maxtime = value["maxtime"].get_int64();
            mintime = value["mintime"].get_int64();

            for (auto obj : value["mutable"].get_array().getValues())
            {
                mutables.push_back(obj.get_str());
            }

            noncerange = value["noncerange"].get_str();

            for (auto obj : value["capabilities"].get_array().getValues())
            {
                capabilities.push_back(obj.get_str());
            }

            reject_reason = value["reject-reason"].get_str();

            return *this;
        }
    };

    // getmininginfo

    class GetMiningInfoResult
    {
    public:
        long long blocks;
        unsigned long long currentblocksize;
        unsigned long long currentblockweight;
        unsigned long long currentblocktx;
        double difficulty;
        string errors;
        bool generate;
        int genproclimit;
        double hashespersec;
        double networkhashps;
        unsigned long long pooledtx;
        bool testnet;

        GetMiningInfoResult &operator=(UniValue value)
        {
            blocks = value["blocks"].get_int64();
            currentblocksize = value["currentblocksize"].get_int64();
            currentblockweight = value["currentblockweight"].get_int64();
            currentblocktx = value["currentblocktx"].get_int64();
            difficulty = value["difficulty"].get_real();
            errors = value["errors"].get_str();
            generate = value["generate"].get_bool();
            genproclimit = value["genproclimit"].get_int();
            hashespersec = value["hashespersec"].get_real();
            networkhashps = value["networkhashps"].get_real();
            pooledtx = value["pooledtx"].get_int64();
            testnet = value["testnet"].get_bool();

            return *this;
        }
    };

    // getnetworkhashps
    // prioritisetransaction
    // submitblock
    // submitheader
} // namespace c2pool::bitcoind::data
#endif