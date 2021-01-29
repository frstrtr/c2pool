#pragma once

#include "uint256.h"
#include "univalue.h"

#include <string>
#include <vector>
#include <map>

//TODO: for debug
#include <iostream>
using std::cout, std::endl;

using std::string, std::vector, std::map;

namespace c2pool::coind::jsonrpc::data
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

    class SoftFork
    {
    public:
        string type;
        bool active;
        int height;

        SoftFork &operator=(UniValue value)
        {
            type = value["type"].get_str();
            active = value["active"].get_bool();
            height = value["height"].get_int();
            return *this;
        }
    };

    class SoftForks
    {
    public:
        map<string, SoftFork> softforks;
        //map<string, Bip9SoftForkDescription> bip9_softforks;

        SoftForks &operator=(UniValue value)
        {
            auto keys = value.getKeys();
            for (auto key : keys)
            {
                softforks[key] = value[key];
            }
            return *this;
        }
    };
} // namespace c2pool::coind::jsonrpc::data

namespace c2pool::coind::jsonrpc::data
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

        uint256 chainwork;
        long long size_on_disk;

        bool pruned;
        SoftForks softforks;

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

            string chainwork_temp = value["chainwork"].get_str();
            chainwork.SetHex(chainwork_temp);

            size_on_disk = value["size_on_disk"].get_int64();
            pruned = value["pruned"].get_bool();
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
} // namespace c2pool::coind::jsonrpc::data

//================================================================
//=========================Mining RPC=============================
//================================================================

//getblocktemplate
namespace c2pool::coind::jsonrpc::data
{
    class GetBlockTemplateResultTx
    {
    public:
        string data;
        uint256 hash;
        uint256 txid;
        vector<long long> depends;
        long long fee;
        long long sigops;
        long long weight;

        GetBlockTemplateResultTx &operator=(UniValue value)
        {
            data = value["data"].get_str();

            string hash_raw = value["hash"].get_str();
            hash.SetHex(hash_raw);

            string txid_raw = value["txid"].get_str();
            txid.SetHex(hash_raw);

            for (auto depend : value["depends"].get_array().getValues())
            {
                depends.push_back(depend.get_int64());
            }

            fee = value["fee"].get_int64();
            sigops = value["sigops"].get_int64();
            weight = value["weight"].get_int64();

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
        // Block proposal from BIP 0023.
        vector<string> capabilities;

        int version;
        vector<string> rules;

        //TODO: vbavailable
        int vbrequired;

        uint256 previousblockhash;
        vector<GetBlockTemplateResultTx> transactions;

        GetBlockTemplateResultAux *coinbaseaux; //TODO: test serialize

        long long *coinbasevalue;
        // Optional long polling from BIP 0022.
        string longpollid;
        //TODO?: string longpolluri;

        // Basic pool extension from BIP 0023.
        string target;

        long long mintime;

        vector<string> mutables; //json:mutable

        string noncerange;

        long long sigoplimit;
        long long sizelimit;
        long long weightlimit;

        string bits;
        long long curtime;
        long long height;

        // Witness commitment defined in BIP 0141.
        string default_witness_commitment;

        GetBlockTemplateResultTx *coinbasetxn;

        /* OLD
            string workid;
            bool *submitold;
            long long expires;
            // Mutations from BIP 0023.
            long long maxtime;
            string reject_reason; //json: reject-reason
        */
    public:
        GetBlockTemplateResult &operator=(UniValue value)
        {
            for (auto obj : value["capabilities"].get_array().getValues())
            {
                capabilities.push_back(obj.get_str());
            }

            version = value["version"].get_int();

            for (auto obj : value["rules"].get_array().getValues())
            {
                rules.push_back(obj.get_str());
            }

            //TODO: vbavailable
            vbrequired = value["vbrequired"].get_int();

            string previousblockhash_raw = value["previousblockhash"].get_str();
            previousblockhash.SetHex(previousblockhash_raw);

            for (auto obj : value["transactions"].get_array().getValues())
            {
                GetBlockTemplateResultTx tx;
                tx = obj.get_obj();
                transactions.push_back(tx);
            }

            if (!value["coinbaseaux"].empty())
            {
                *coinbaseaux = value["coinbaseaux"].get_obj();
            }

            if (!value["coinbasevalue"].isNull())
            {
                *coinbasevalue = value["coinbasevalue"].get_int64();
            }

            longpollid = value["longpollid"].get_str();
            target = value["target"].get_str(); //TODO: uint256?
            mintime = value["mintime"].get_int64();


            for (auto obj : value["mutable"].get_array().getValues())
            {
                mutables.push_back(obj.get_str());
            }

            noncerange = value["noncerange"].get_str();

            sigoplimit = value["sigoplimit"].get_int64();
            sizelimit = value["sizelimit"].get_int64();
            weightlimit = value["weightlimit"].get_int64();

            bits = value["bits"].get_str();
            curtime = value["curtime"].get_int64();
            height = value["height"].get_int64();

            default_witness_commitment = value["default_witness_commitment"].get_str();

            if (!value["coinbasetxn"].isNull())
            {
                *coinbasetxn = value["coinbasetxn"].get_obj();
            }
            
            /* OLD:
            workid = value["workid"].get_str();
            longpolluri = value["longpolluri"].get_str();
            *submitold = value["submitold"].get_bool(); //TODO: ? nullptr
            expires = value["expires"].get_int64();
            maxtime = value["maxtime"].get_int64();
            reject_reason = value["reject-reason"].get_str();
            */

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
} // namespace c2pool::coind::jsonrpc::data