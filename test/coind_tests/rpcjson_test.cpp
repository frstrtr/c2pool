#include <gtest/gtest.h>
#include <tuple>
#include <string>
#include <vector>
#include <sstream>
#include <iostream>

#include <libcoind/jsonrpc/coind.h>

#ifdef PASS_EXIST
#include "pass.h"
#endif

using namespace coind::jsonrpc;
using namespace coind::jsonrpc::data;
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
        coind = new Coind(username, password, addr, std::make_shared<coind::DigibyteParentNetwork>());

#else
        coind = new Coind("bitcoin", "B1TC01ND", "http://127.0.0.1:8332/", std::make_shared<c2pool::DigibyteNetwork>());
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
    cout << "getblockchaininfo.bestblockhash = " << result["bestblockhash"].get_str() << endl;
    cout << result.write() << endl;
}

TEST_F(Bitcoind_JSONRPC, getblocktemplate)
{
    vector<string> rules{"segwit"};
    GetBlockTemplateRequest *request = new GetBlockTemplateRequest(rules);

    auto result = coind->getblocktemplate(request);
    cout << result["version"].get_int() << endl;
}

TEST_F(Bitcoind_JSONRPC, getblock)
{
    uint256 block_hash;
    block_hash.SetHex("a058f7934d45061a3431617330e21c4ea4d07b8bb6179471a4680366aee92b4f");
    GetBlockRequest *request = new GetBlockRequest(block_hash);
    
    auto result = coind->GetBlock(request);
    cout << result.write() << endl;
}

TEST_F(Bitcoind_JSONRPC, getnetworkinfo)
{   
    auto result = coind->GetNetworkInfo();
    cout << result.write() << endl;
}