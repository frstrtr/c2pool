#ifndef JSONRPC_BITCOIND_H
#define JSONRPC_BITCOIND_H

#include "requests.h"
#include "results.h"
#include "univalue.h"

#include <stdio.h>

#include <curl/curl.h>

#include <string>
#include <cstring>

using std::string;
using namespace c2pool::bitcoind::data;

namespace c2pool::bitcoind
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

                char *userpwd = new char[150];
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

        std::string request(std::string command, c2pool::bitcoind::data::TemplateRequest *req = nullptr)
        {
            std::string json_answer = "";
            char *params = "";
            if (req)
            {
                params = req->get_params().c_str();
            }
            if (curl)
            {
                char *data = new char[strlen(dataFormat) + req->get_length() + 1];
                sprintf(data, dataFormat, command, params);

                curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_data);
                curl_easy_setopt(curl, CURLOPT_WRITEDATA, &json_answer);

                CURLcode res = curl_easy_perform(curl);

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
            UniValue jsonValue(UniValue::VOBJ);
            jsonValue.read(json);
            GetBlockChainInfoResult result = jsonValue;
            return result;
        }

        //https://bitcoincore.org/en/doc/0.18.0/rpc/mining/getblocktemplate/
        GetBlockTemplateResult GetBlockTemplate(GetBlockTemplateRequest* req)
        {
            string json = request("getblockchaininfo", req);
            UniValue jsonValue(UniValue::VOBJ);
            jsonValue.read(json);
            GetBlockTemplateResult result = jsonValue;
            return result;
        }
    } // namespace c2pool::bitcoind

#endif