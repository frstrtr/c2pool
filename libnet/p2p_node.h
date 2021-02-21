#pragma once

#include "p2p_protocol.h"

namespace c2pool::libnet::p2p
{
    class Protocol;
}

#include <boost/asio.hpp>
namespace io = boost::asio;
namespace ip = boost::asio::ip;

#include <set>
#include <tuple>
#include <map>
#include <memory>
using std::set, std::tuple, std::map;
using std::shared_ptr, std::unique_ptr;

#include <devcore/addrStore.h>

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

    //TODO: Protocol;
    // namespace p2p
    // {
    //     class Protocol;
    // }
} // namespace c2pool

#define HOST_IDENT std::string

using namespace c2pool::libnet;

namespace c2pool::libnet::p2p
{
    class P2PNode
    {
    public:
        P2PNode(shared_ptr<NodeManager> _mngr, const ip::tcp::endpoint &listen_ep);
        void start();

        std::vector<ADDR> get_good_peers(int max_count);

    private:
        bool protocol_connected(shared_ptr<c2pool::libnet::p2p::Protocol> protocol); //todo

        void listen();
        void auto_connect();

    private:
        shared_ptr<NodeManager> _manager;
        shared_ptr<c2pool::dev::coind_config> _config;
        unique_ptr<std::thread> _thread;
        shared_ptr<io::steady_timer> _auto_connect_timer;
        const std::chrono::milliseconds auto_connect_interval{1000L};

        io::io_context _context;
        //client
        ip::tcp::resolver _resolver;
        //server
        ip::tcp::acceptor _acceptor;

    private:
        unsigned long long node_id; //nonce

        set<HOST_IDENT> client_attempts;
        set<int /*TODO: Protocol*/> client_connections;
        map<HOST_IDENT, int> server_connections;
    };
} // namespace c2pool::p2p