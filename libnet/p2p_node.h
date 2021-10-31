#pragma once

#include <set>
#include <tuple>
#include <map>
#include <memory>
#include <chrono>

#include <boost/asio.hpp>

#include <libdevcore/addrStore.h>

namespace io = boost::asio;
namespace ip = boost::asio::ip;
using std::set, std::tuple, std::map;
using std::shared_ptr, std::unique_ptr;

namespace c2pool
{
    namespace libnet
    {
        namespace p2p
        {
            class Protocol;
            class P2PSocket;
        }
    }

    namespace dev
    {
        class coind_config;
    }
} // namespace c2pool

#define HOST_IDENT std::string

using namespace c2pool::libnet;

namespace c2pool::libnet::p2p
{
    class P2PNode : public std::enable_shared_from_this<P2PNode>
    {
    public:
        P2PNode(std::shared_ptr<io::io_context> __context);
        void start();

        std::vector<addr> get_good_peers(int max_count);
        unsigned long long get_nonce();
        bool is_connected() const;

    private:
        bool protocol_connected(shared_ptr<c2pool::libnet::p2p::Protocol> protocol);
        bool protocol_listen_connected(shared_ptr<c2pool::libnet::p2p::Protocol> protocol);

        void listen();
        void auto_connect();

    private:
        shared_ptr<c2pool::dev::coind_config> _config;
        shared_ptr<io::io_context> _context; //From NodeManager;
        shared_ptr<c2pool::dev::AddrStore> _addr_store;
        io::steady_timer _auto_connect_timer;
        const std::chrono::seconds auto_connect_interval{std::chrono::seconds(1)};

        //client
        ip::tcp::resolver _resolver;
        //server
        ip::tcp::acceptor _acceptor;

    private:
        unsigned long long node_id; //nonce

        map<HOST_IDENT, shared_ptr<P2PSocket>> client_attempts;
        set<shared_ptr<P2PSocket>> server_attempts;
        set<shared_ptr<c2pool::libnet::p2p::Protocol>> client_connections;
        map<HOST_IDENT, int> server_connections;
    };
} // namespace c2pool::p2p