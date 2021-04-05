#pragma once

#include <iostream>

#include "univalue.h"
#include <btclibs/uint256.h>

#include <string>
#include <vector>
using std::string;
using std::vector;

//In request class constructor only required agruments, without optional.

namespace c2pool::coind::jsonrpc::data
{
    class TemplateRequest
    {
    protected:
        UniValue params;

    public:
        const string command;

    protected:
        virtual void set_params() = 0;

    public:
        TemplateRequest(string cmd) : command(cmd)
        {
            params = UniValue(UniValue::VARR);
        }

        virtual string get_params()
        {
            if (params.empty())
            {
                set_params();
            }
            return params.write();
        }

        size_t get_length()
        {
            return get_params().length();
        }
    };

    class GetBlockRequest : public TemplateRequest
    {
    public:
        //required
        uint256 blockhash;

    public:
        //optional
        int verbosity; //default = 1
    public:
        GetBlockRequest(uint256 _blockhash, int _verbosity = 1) : TemplateRequest("getblock")
        {
            blockhash = _blockhash;
            verbosity = _verbosity;
        }

        void set_params() override
        {
            params.push_back(blockhash.ToString());
            params.push_back(verbosity);
        }
    };

    class GetBlockHeaderRequest : public TemplateRequest
    {
    public:
        //required
        uint256 blockhash;

    public:
        //optional
        bool verbose; //default = true
    public:
        GetBlockHeaderRequest(uint256 _blockhash, bool _verbose = true) : TemplateRequest("getblockheader")
        {
            blockhash = _blockhash;
            verbose = _verbose;
        }

        void set_params() override
        {
            params.push_back(blockhash.ToString());
            params.push_back(verbose);
        }
    };

    class GetBlockTemplateRequest : public TemplateRequest
    {
    public:
        //required
        std::vector<string> rules;

    public:
        //optional
        std::string mode;
        std::vector<string> capabilities;

    public:
        GetBlockTemplateRequest() : TemplateRequest("getblocktemplate")
        {
        }

        GetBlockTemplateRequest(vector<string> _rules) : TemplateRequest("getblocktemplate")
        {
            rules = _rules;
        }

        void set_params() override
        {
            UniValue _rules(UniValue::VOBJ);
            UniValue _rules_list(UniValue::VARR);
            for (auto _rule : rules)
            {
                _rules_list.push_back(_rule);
            }
            _rules.pushKV("rules", _rules_list);
            params.push_back(_rules);

            if (!mode.empty())
            {
                params.push_back(mode);
                //params.pushKV("mode", mode);
            }

            if (!capabilities.empty())
            {
                UniValue _capabilities(UniValue::VOBJ);
                UniValue _capabilities_list(UniValue::VARR);
                for (auto capa : capabilities)
                {
                    _capabilities_list.push_back(capa);
                }
                _capabilities.pushKV("capabilities", _capabilities_list);
                params.push_back(_capabilities);
                // capabilities.clear();
            }
        }
    };
} // namespace c2pool::coind::data