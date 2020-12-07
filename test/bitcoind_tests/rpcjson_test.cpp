#include <gtest/gtest.h>
#include <tuple>
#include <string>
#include <vector>
#include <sstream>
#include <iostream>

#include "jsonrpc-bitcoind/bitcoind.h"

using namespace c2pool::bitcoind;
using namespace c2pool::bitcoind::data;
using namespace std;

class Bitcoind_JSONRPC : public ::testing::Test
{
protected:
    c2pool::bitcoind::Bitcoind* bitcoind;
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
        bitcoind = new c2pool::bitcoind::Bitcoind("bitcoin", "B1TC01ND", "http://127.0.0.1:8332/");
    }

    virtual void TearDown()
    {
        delete bitcoind;
    }
};

TEST_F(Bitcoind_JSONRPC, getblockchaininfo)
{
    GetBlockChainInfoResult result = bitcoind->GetBlockChainInfo();
    cout << result.bestblockhash << endl;
}

TEST_F(Bitcoind_JSONRPC, getblocktemplate)
{
    vector<string> rules{"segwit"};
    rules.push_back("segwit");
    GetBlockTemplateRequest request(rules);

    GetBlockTemplateResult result = bitcoind->GetBlockChainInfo(request);
    cout << result.version << endl;
}