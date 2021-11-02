#include <gtest/gtest.h>
#include <libnet/coind_node.h>
#include <libcoind/jsonrpc/coind.h>
#include <boost/asio.hpp>

using namespace c2pool::libnet;

class TestNode
{
public:
// private:
    std::shared_ptr<boost::asio::io_context> _context; //From NodeManager
    boost::asio::deadline_timer work_poller_t;

// private:
    shared_ptr<coind::ParentNetwork> _parent_net;
    shared_ptr<coind::jsonrpc::Coind> _coind;

// private:

    ip::tcp::resolver _resolver;

public:
    TestNode(std::shared_ptr<boost::asio::io_context> __context, shared_ptr<coind::ParentNetwork> __parent_net, shared_ptr<coind::jsonrpc::Coind> __coind) : _context(__context), _parent_net(__parent_net), _coind(__coind), _resolver(*_context), work_poller_t(*_context)
    {
    }
};

TEST(Libnet, CoindNode_Init)
{
    auto context = std::make_shared<boost::asio::io_context>();
    auto parent_net = std::make_shared<coind::DigibyteParentNetwork>();
    //coind=======
    const char *username = "1";
    const char *password = "2";
    const char *address = "3";
    auto coind = std::make_shared<coind::jsonrpc::Coind>(username, password, address, parent_net);
    //============
    std::cout << "test1" << endl;
    boost::asio::deadline_timer _timer(*context);
    std::cout << "test1.5" << endl;
    TestNode test_node(context, parent_net, coind);
    std::cout << "test1.75" << endl;
    CoindNode coind_node(context, parent_net, coind);
    std::cout << "test2" << endl;
}