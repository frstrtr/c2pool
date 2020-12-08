#ifndef JSONRPC_BITCOIND_H
#define JSONRPC_BITCOIND_H

#include "requests.h"
#include "results.h"
#include "univalue.h"

#include <stdio.h>

#include <curl/curl.h>

#include <string>
#include <cstring>
#include <iostream>

using std::string;
using namespace c2pool::bitcoind::jsonrpc::data;

namespace c2pool::bitcoind::jsonrpc
{
    class Bitcoind
    {
    private:
        CURL *curl;

        const char *dataFormat =
            "{\"jsonrpc\": \"2.0\", \"id\":\"curltest\", \"method\": \"%s\", \"params\": [%s] }";

    public:
        Bitcoind(char *username, char *password, char *address)
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

        ~Bitcoind()
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

        std::string request(std::string command, c2pool::bitcoind::jsonrpc::data::TemplateRequest *req = nullptr)
        {
            std::string json_answer = "";
            char *params = "";
            if (req != nullptr)
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
                printf("%s\n", data);

                curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)strlen(data));
                curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data);

                curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_data);
                curl_easy_setopt(curl, CURLOPT_WRITEDATA, &json_answer);

                CURLcode res = curl_easy_perform(curl);
                if (!res){
                    std::cout << res << std::endl; //TODO: DEBUG ERROR
                }
                //TODO: [FOR DEBUG]:
                // if (!res)
                //     std::cout << content << std::endl;
                // else
                //     std::cerr << "1" << curl_easy_strerror(res) << std::endl;
            }
            return json_answer;
        }

    public:
        GetBlockChainInfoResult GetBlockChainInfo()
        {

            string json = request("getblockchaininfo");
            std::cout << json << std::endl;
            UniValue jsonValue(UniValue::VOBJ);
            jsonValue.read(json);
            GetBlockChainInfoResult result;
            result = jsonValue;
            return result;
        }

        //https://bitcoincore.org/en/doc/0.18.0/rpc/mining/getblocktemplate/
        GetBlockTemplateResult GetBlockTemplate(GetBlockTemplateRequest *req)
        {
            string json = request("getblockchaininfo", req);
            UniValue jsonValue(UniValue::VOBJ);
            jsonValue.read(json);
            GetBlockTemplateResult result;
            result = jsonValue;
            return result;
        }
    }; // namespace c2pool::bitcoind
} // namespace c2pool::bitcoind::jsonrpc
#endif