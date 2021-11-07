#include <gtest/gtest.h>
#include <tuple>
#include <string>
#include <vector>
#include <iostream>

#include <boost/asio.hpp>
#include <boost/asio/buffer.hpp>
namespace net = boost::asio;
using tcp = net::ip::tcp;

#include <libcoind/jsonrpc/coind.h>
#include <libcoind/jsonrpc/jsonrpc_coind.h>

#ifdef PASS_EXIST
#include "pass.h"
#endif

using namespace coind::jsonrpc;
using namespace coind::jsonrpc::data;
using namespace std;

class Bitcoind_JSONRPC : public ::testing::Test
{
protected:
	std::shared_ptr<coind::JSONRPC_Coind> coind;

protected:

    virtual void SetUp()
    {
#ifdef PASS_EXIST
		auto context = std::make_shared<boost::asio::io_context>(2);

		auto _pass = get_pass();
		char *login = std::get<0>(_pass);
		char *addr = std::get<1>(_pass);
		char *port = std::get<2>(_pass);
		coind = std::make_shared<coind::JSONRPC_Coind>(context, std::make_shared<coind::DigibyteParentNetwork>(), addr, port, login);

#else
        coind = new Coind("bitcoin", "B1TC01ND", "http://127.0.0.1:8332/", std::make_shared<c2pool::DigibyteNetwork>());
#endif
    }

    virtual void TearDown()
    {

    }
};

TEST_F(Bitcoind_JSONRPC, getblockchaininfo)
{
	auto result = coind->getblockchaininfo();
	std::cout << result.write() << std::endl;
	ASSERT_EQ(result["chain"].get_str(), "main");
}

TEST_F(Bitcoind_JSONRPC, getmininginfo)
{
	auto result = coind->getmininginfo();
	std::cout << result.write() << std::endl;
	ASSERT_EQ(result["chain"].get_str(), "main");
}

TEST_F(Bitcoind_JSONRPC, getblock)
{
	uint256 block_hash;
	block_hash.SetHex("36643871691af2e0b6bfc7898a4399133c6e6e4885a67f9d9fe36942c2513772");
	auto getblock_req = std::make_shared<GetBlockRequest>(block_hash);

	auto result = coind->getblock(getblock_req);
	std::cout << result.write() << std::endl;
	ASSERT_EQ(result["nonce"].get_int(), 328117616);
}

TEST_F(Bitcoind_JSONRPC, getwork)
{
	coind::TXIDCache txidcache;
	map<uint256, coind::data::tx_type> known_txs;
	auto result = coind->getwork(txidcache, known_txs, false);
}