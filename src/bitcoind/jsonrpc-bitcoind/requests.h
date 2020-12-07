#ifndef JSONRPC_BITCOIND_REQUESTS_H
#define JSONRPC_BITCOIND_REQUESTS_H

#include "univalue.h"

#include <string>
#include <vector>
using std::vector, std::string;

//In request class constructor only required agruments, without optional.

namespace c2pool::bitcoind::data
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
            params = UniValue(UniValue::VOBJ);
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

    class GetBlockTemplateRequest : public TemplateRequest
    {
    public:
        //required
        std::vector<string> rules;

    public:
        //optional
        std::string *mode;
        std::vector<string> capabilities;

    public:
        GetBlockTemplateRequest(vector<string> _rules) : TemplateRequest("getblocktemplate")
        {
            rules = _rules;
        }

        void set_params() override
        {
            UniValue _rules(UniValue::VARR);
            for (auto _rule : rules)
            {
                _rules.push_back(_rule);
            }
            params.pushKV("rules", _rules);

            if (mode)
            {
                params.pushKV("mode", *mode);
                delete mode;
            }

            if (!capabilities.empty())
            {
                UniValue _capabilities(UniValue::VARR);
                for (auto capa : capabilities)
                {
                    _capabilities.push_back(capa);
                }
                params.pushKV("capabilities", _capabilities);
                // capabilities.clear();
            }
        }
    };
} // namespace c2pool::bitcoind::data

#endif