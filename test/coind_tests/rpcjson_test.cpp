#include <gtest/gtest.h>
#include <tuple>
#include <string>
#include <vector>
#include <iostream>

#include <boost/asio.hpp>
#include <boost/asio/buffer.hpp>
namespace net = boost::asio;
using tcp = net::ip::tcp;

#include <libdevcore/common.h>
#include <libcoind/jsonrpc/jsonrpc_coind.h>
#include <thread>

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
    auto result = coind->getwork(txidcache, known_txs);

    std::cout << "version: " << result.version << std::endl;
    std::cout << "previous_block: " << result.previous_block.GetHex() << std::endl;
    std::cout << "transactions: ";
    for (auto v: result.transactions) {
        std::cout << v->version << std::endl;
    }
    std::cout << std::endl;

}

TEST_F(Bitcoind_JSONRPC, multi_getwork)
{
    coind::TXIDCache txidcache;
    map<uint256, coind::data::tx_type> known_txs;

    for (int i = 0; i < 10; i++) {
        auto result = coind->getwork(txidcache, known_txs);

        std::cout << "version: " << result.version << std::endl;
        std::cout << "previous_block: " << result.previous_block.GetHex() << std::endl;
        std::cout << "transactions: ";
        for (auto v: result.transactions) {
            std::cout << v->version << std::endl;
        }
        std::cout << std::endl;
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
}

TEST(RPC_DATA, swap4_test)
{
    PackStream stream;
    auto v = uint256S("75bcd15");
    IntType(256) i(v);
    auto data = c2pool::dev::swap4(stream.data);
    std::cout << HexStr(data) << std::endl;
}