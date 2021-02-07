#pragma once
#include <boost/asio.hpp>
namespace io = boost::asio;
namespace ip = boost::asio::ip;

#include <memory>
using std::shared_ptr;

namespace c2pool
{
    namespace libnet
    {
        class NodeManager;
    }

    namespace dev
    {
        class coind_config;
    }
} // namespace c2pool

using namespace c2pool::libnet;

namespace c2pool::p2p
{
    class P2PNode
    {
    public:
        P2PNode(shared_ptr<NodeManager> _mngr);
        void start();
    private:
        void protocol_connected(); //todo

        void listen();
        void auto_connect();

    private:
        shared_ptr<NodeManager> _manager;
        shared_ptr<c2pool::dev::coind_config> _config;
        std::unique_ptr<std::thread> _thread;
        
        io::io_context _context;
        //client
        ip::tcp::resolver _resolver;
        //server
        ip::tcp::acceptor _acceptor;
    private:
        unsigned long long node_id; //nonce
    };
} // namespace c2pool::p2p