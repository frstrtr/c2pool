#include <gtest/gtest.h>
#include <libnet/p2p_node.h>

#include <iostream>
using namespace std;
using namespace chrono_literals;

class Libnet_P2PNode : public ::testing::Test
{
protected:
    boost::asio::thread_pool pool;

    std::shared_ptr<boost::asio::io_context> _context;
    std::shared_ptr<c2pool::DigibyteNetwork> _net;
    std::shared_ptr<c2pool::dev::coind_config> _config;
    std::shared_ptr<c2pool::dev::AddrStore> _addr_store;
    std::shared_ptr<c2pool::libnet::p2p::P2PNode> _p2pnode;

protected:

    virtual void SetUp()
    {
        boost::asio::post(pool, [&](){
            _context = make_shared<boost::asio::io_context>();
            _net = std::make_shared<c2pool::DigibyteNetwork>();
            _config = std::make_shared<c2pool::dev::coind_config>();
            _addr_store = std::make_shared<c2pool::dev::AddrStore>("data//digibyte//addrs", _net);

            _p2pnode = std::make_shared<c2pool::libnet::p2p::P2PNode>(_context, _net, _config, _addr_store);
            _p2pnode->start();//_context::post???
            std::cout << "run" << std::endl;
            _context->run();
        });
    }

    virtual void TearDown()
    {

    }
};


TEST_F(Libnet_P2PNode, Init)
{

    for (int i = 0; i < 20; i++)
    {
        std::this_thread::sleep_for(1s);
        std::cout << "test" << std::endl;
    }
    _context->stop();
}