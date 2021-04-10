#include <gtest/gtest.h>
#include <tuple>
#include <string>
#include <sstream>
#include <iostream>
#include <memory>
using namespace std;

#include <boost/bind.hpp>
#include <boost/asio.hpp>
namespace io = boost::asio;
namespace ip = boost::asio::ip;

#include <coind/p2p/p2p_socket.h>
#include <coind/p2p/p2p_protocol.h>

#include <networks/network.h>

class TestCoindNode
{
public:
    io::io_context _context;
    ip::tcp::resolver _resolver;
    shared_ptr<coind::p2p::CoindProtocol> protocol;
    shared_ptr<coind::ParentNetwork> net;

public:
    TestCoindNode() : _context(1), _resolver(_context)
    {
        net = make_shared<coind::DigibyteParentNetwork>();
    }

    void start(string ip)
    {
        _resolver.async_resolve(ip, std::to_string(net->P2P_PORT), [this](const boost::system::error_code &er, const boost::asio::ip::tcp::resolver::results_type endpoints) {
            cout << "in start connected" << endl;
            ip::tcp::socket socket(_context);
            auto _socket = make_shared<coind::p2p::P2PSocket>(std::move(socket), net);

            protocol = make_shared<coind::p2p::CoindProtocol>(_socket, net);
            _socket->init(endpoints, protocol);
        });

        _context.run();
    }
};

class Coind_P2P : public ::testing::Test
{
protected:
    shared_ptr<TestCoindNode> node;

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
        node = make_shared<TestCoindNode>();
        node->start("217.72.6.241");
    }

    virtual void TearDown()
    {
        //delete coind;
    }
};

TEST_F(Coind_P2P, test_connection)
{
    // auto result = coind->GetBlockChainInfo();
    // cout << "getblockchaininfo.bestblockhash = " << result["bestblockhash"].get_str() << endl;
    // cout << result.write() << endl;
}