#include <gtest/gtest.h>
#include <tuple>
#include <string>
#include <vector>
#include <sstream>
#include <iostream>

#include <coind/jsonrpc-coind/coind.h>

#ifdef PASS_EXIST
#include "pass.h"
#endif

using namespace c2pool::coind::jsonrpc;
using namespace c2pool::coind::jsonrpc::data;
using namespace std;

class Bitcoind_JSONRPC : public ::testing::Test
{
protected:
    Coind *coind;

protected:
    template <typename UINT_TYPE>
    UINT_TYPE CreateUINT(string hex)
    {
        UINT_TYPE _number;
        _number.SetHex(hex);
        return _number;
    }

    virtual void SetUp()
    {
#ifdef PASS_EXIST
        auto _pass = get_pass();
        char* username = std::get<0>(_pass);
        char* password = std::get<1>(_pass);
        char* addr = std::get<2>(_pass);
        coind = new Coind(username, password, addr);

#else
        coind = new Coind("bitcoin", "B1TC01ND", "http://127.0.0.1:8332/");
#endif
    }

    virtual void TearDown()
    {
        delete coind;
    }
};

TEST_F(Bitcoind_JSONRPC, getblockchaininfo)
{
    auto result = coind->GetBlockChainInfo();
    cout << result["bestblockhash"].get_str() << endl;
    cout << result.write() << endl;
}

TEST_F(Bitcoind_JSONRPC, getblocktemplate)
{
    vector<string> rules{"segwit"};
    rules.push_back("segwit");
    GetBlockTemplateRequest *request = new GetBlockTemplateRequest(rules);

    auto result = coind->GetBlockTemplate(request);
    cout << result["version"].get_int() << endl;
}