#pragma once

#include "requests.h"
#include "results.h"
#include "univalue.h"

#include <stdio.h>

#include <curl/curl.h>

#include <string>
#include <cstring>
#include <iostream>

using std::string;
using namespace c2pool::coind::jsonrpc::data;

namespace c2pool::coind::jsonrpc
{
    class Coind
    {
    private:
        CURL *curl;

        const char *dataFormat =
            "{\"jsonrpc\": \"2.0\", \"id\":\"curltest\", \"method\": \"%s\", \"params\": [%s] }";

    public:
        Coind(char *username, char *password, char *address)
        {
            curl = curl_easy_init();

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

        UniValue request(std::string command, c2pool::coind::jsonrpc::data::TemplateRequest *req = nullptr)
        {
            UniValue result;
            result.setNull();
            std::string json_answer = "";
            char *params = "";
            if (req)
            {
                params = new char[req->get_params().length() + 1];
                strcpy(params, req->get_params().c_str());
                //params = req->get_params().c_str();
            }
            if (curl)
            {
                long data_length = strlen(dataFormat) + 1 + command.length();
                if (req)
                    data_length += req->get_length();
                char *data = new char[data_length];
                sprintf(data, dataFormat, command.c_str(), params);
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

            if (json_answer.empty())
            {
                return result;
            }
            //std::cout << json_answer << std::endl; //TODO: DEBUG LOG
            result.read(json_answer);

            if (!result["error"].isNull())
            {
                //TODO: DEBUG ERROR << result["error"].get_str();
            }
            return result["result"].get_obj();
        }

    public:
        //https://bitcoin-rpc.github.io/en/doc/0.17.99/rpc/blockchain/getblockchaininfo/
        UniValue GetBlockChainInfo()
        {
            UniValue jsonValue = request("getblockchaininfo");
            return jsonValue;
        }

        UniValue GetBlock(uint256 hash, int verbosity = 1){
            
        }

        //https://bitcoincore.org/en/doc/0.18.0/rpc/mining/getblocktemplate/
        UniValue GetBlockTemplate(GetBlockTemplateRequest *req)
        {
            UniValue jsonValue = request("getblocktemplate", req);
            return jsonValue;
        }
    }; // namespace c2pool::coind
} // namespace c2pool::coind::jsonrpc