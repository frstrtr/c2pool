#ifndef JSONRPC_BITCOIND_REQUESTS_H
#define JSONRPC_BITCOIND_REQUESTS_H

#include <string>
using std::string;

namespace c2pool::bitcoind::data
{
    class TemplateRequest
    {
    protected:
        string params;

    public:
        const std::string command;

    public:
        virtual string get_params() = 0;

        size_t get_length()
        {
            return get_params().length();
        }
    };
} // namespace c2pool::bitcoind::data

#endif