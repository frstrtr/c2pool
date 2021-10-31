#pragma once

#include "requests.h"
#include "results.h"
#include "univalue.h"
#include <networks/network.h>
#include <libdevcore/common.h>

#include <stdio.h>

#include <curl/curl.h>

#include <string>
#include <cstring>
#include <iostream>
#include <memory>
#include <map>

//#include <libdevcore/logger.h>

using std::shared_ptr, std::make_shared;
using std::string, std::map;
using namespace coind::jsonrpc::data;

namespace coind::data
{
    class TransactionType;
}

namespace coind::jsonrpc
{
    class TXIDCache
    {
    public:
        map<string, uint256> cache; //getblocktemplate.transacions[].data; hash256(packed data)
    private:
        bool _started = false;

        time_t time_started = 0;

    public:
        bool is_started() const
        {
            return _started;
        }

        bool exist(const string &key)
        {
            return (cache.find(key) != cache.end());
        }

        uint256 operator[](const string &key)
        {
            if (exist(key))
            {
                return cache[key];
            }
            else
            {
                uint256 null_value;
                null_value.SetNull();
                return null_value;
            }
        }

        void add(const string &key, const uint256 &value)
        {
            cache[key] = value;
        }

        void add(map<string, uint256> v)
        {
            for (auto _v : v)
            {
                cache[_v.first] = _v.second;
            }
        }

        void clear()
        {
            cache.clear();
        }

        void start()
        {
            time_started = c2pool::dev::timestamp();
            _started = true;
        }

        time_t time()
        {
            return time_started;
        }
    };
}

namespace coind::jsonrpc
{
    class Coind : public std::enable_shared_from_this<Coind>
    {
    private:
        CURL *curl;
        shared_ptr<coind::ParentNetwork> _parent_net;

        const char *dataFormat =
            "{\"jsonrpc\": \"2.0\", \"id\":\"curltest\", \"method\": \"%s\", \"params\": %s }";

    public:
        Coind(const char *username, const char *password, const char *address, shared_ptr<coind::ParentNetwork> parent_net) : _parent_net(parent_net)
        {
            curl = curl_easy_init();
            //TODO: try/catch
            if (curl)
            {
                struct curl_slist *headers = NULL;
                headers = curl_slist_append(headers, "content-type: text/plain;");
                curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

                curl_easy_setopt(curl, CURLOPT_URL, address); //"http://127.0.0.1:8332/"

                char *userpwd = new char[strlen(username) + strlen(password) + 1];
                sprintf(userpwd, "%s:%s", username, password);
                curl_easy_setopt(curl, CURLOPT_USERPWD, userpwd); //"bitcoin:B1TC01ND"

                //curl_easy_setopt(curl, CURLOPT_USE_SSL, CURLUSESSL_TRY);
            }
        }

        ~Coind()
        {
            curl_easy_cleanup(curl);
        }

    private:
        static size_t write_data(char *ptr, size_t size, size_t nmemb, std::string *data)
        {
            if (data)
            {
                data->append(ptr, size * nmemb);
                return size * nmemb;
            }
            else
                return 0; //error
        }

        UniValue _request(std::string command, coind::jsonrpc::data::TemplateRequest *req = nullptr)
        {
            UniValue result;
            result.setNull();
            std::string json_answer = "";
            char *data(NULL);
            char *params = new char[3];
            strcpy(params, "[]");
            if (req)
            {
                params = new char[req->get_params().length() + 1];
                strcpy(params, req->get_params().c_str());
                //std::cout << params << std::endl;
                //params = req->get_params().c_str();
            }
            if (curl)
            {
                long data_length = strlen(dataFormat) + 1 + command.length();
                if (req)
                    data_length += req->get_length();
                data = new char[data_length];
                sprintf(data, dataFormat, command.c_str(), params);
                //std::cout << data << std::endl;
                //printf("%s\n", data);

                curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)strlen(data));
                curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data);

                curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_data);
                curl_easy_setopt(curl, CURLOPT_WRITEDATA, &json_answer);

                CURLcode res = curl_easy_perform(curl);
                if (res)
                {
                    std::cout << "res curl error: " << res << std::endl; //TODO: DEBUG ERROR
                }
                //TODO: [FOR DEBUG]:
                // if (!res)
                //     std::cout << content << std::endl;
                // else
                //     std::cerr << "1" << curl_easy_strerror(res) << std::endl;
            }

            delete req;
            if (data)
                delete[] data;
            if (params)
                delete[] params;

            if (json_answer.empty())
            {
                return result;
            }
            //std::cout << json_answer << std::endl; //TODO: DEBUG LOG
            result.read(json_answer);

            return result;
        }

        UniValue request(std::string command, coind::jsonrpc::data::TemplateRequest *req = nullptr)
        {
            auto result = _request(command, req);

            if (!result["error"].isNull())
            {
                //LOG_ERROR << result["error"].get_str();
                std::cout << "CURL ERROR: " << result["error"].get_str() << std::endl;
            }
            return result["result"].get_obj();
        }

        //return data with "error" and etc...
        UniValue request_full_data(std::string command, coind::jsonrpc::data::TemplateRequest *req = nullptr)
        {
            return _request(command, req);
        }

        enum coind_error_codes
        {
            MethodNotFound = -32601
        };

        //https://github.com/bitcoin/bitcoin/blob/master/src/rpc/protocol.h
        //0 = OK!
        int check_error(UniValue result)
        {
            if (result.exists("error"))
            {
                if (result["error"].empty())
                {
                    return 0;
                }
            }
            else
            {
                return 0;
            }

            //-----------
            auto error_obj = result["error"].get_obj();
            int actual_error_code = error_obj["code"].get_int();
            string actual_error_msg = error_obj["message"].get_str();

            //TODO: log actual_error_msg!

            return actual_error_code;
        }

    public:
        //in p2pool, that helper.py:

        bool check();

        bool check_block_header(uint256);

        getwork_result getwork(TXIDCache &txidcache, const map<uint256, coind::data::tx_type>& known_txs = map<uint256, coind::data::tx_type>(), bool use_getblocktemplate = false);

    public:
        //https://bitcoin-rpc.github.io/en/doc/0.17.99/rpc/blockchain/getblockchaininfo/
        UniValue GetBlockChainInfo(bool full = false)
        {
            if (full)
                return request_full_data("getblockchaininfo");
            else
                return request("getblockchaininfo");
        }

        UniValue GetNetworkInfo()
        {
            UniValue jsonValue = request("getnetworkinfo");
            return jsonValue;
        }

        UniValue GetBlock(GetBlockRequest *req)
        {
            UniValue jsonValue = request("getblock", req);
            return jsonValue;
        }

        UniValue getblockheader(GetBlockHeaderRequest *req, bool full = false)
        {
            if (full)
                return request_full_data("getblockheader", req);
            else
                return request("getblockheader", req);
        }

        //https://bitcoincore.org/en/doc/0.18.0/rpc/mining/getblocktemplate/
        UniValue getblocktemplate(GetBlockTemplateRequest *req, bool full = false)
        {
            if (full)
                return request_full_data("getblocktemplate", req);
            else
                return request("getblocktemplate", req);
        }

        UniValue getmemorypool(bool full = false)
        {
            if (full)
                return request_full_data("getmemorypool");
            else
                return request("getmemorypool");
        }
    }; // namespace coind
} // namespace coind::jsonrpc