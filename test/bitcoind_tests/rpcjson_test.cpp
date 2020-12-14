#include <gtest/gtest.h>
#include <tuple>
#include <string>
#include <vector>
#include <sstream>
#include <iostream>

#include "jsonrpc-bitcoind/bitcoind.h"

using namespace c2pool::bitcoind::jsonrpc;
using namespace c2pool::bitcoind::jsonrpc::data;
using namespace std;

class Bitcoind_JSONRPC : public ::testing::Test
{
protected:
    Bitcoind* bitcoind;
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
        //bitcoind = new Bitcoind("bitcoin", "B1TC01ND", "http://127.0.0.1:8332/");
        bitcoind = new Bitcoind("Daniil", "Just_the_place_for_a_Snark", "http://217.72.4.157:8332/");
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
    GetBlockTemplateRequest* request = new GetBlockTemplateRequest(rules);

    GetBlockTemplateResult result = bitcoind->GetBlockTemplate(request);
    cout << result.version << endl;
}