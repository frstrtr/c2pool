#pragma once

#include <map>
#include <set>
#include <memory>
#include <numeric>
#include <functional>
#include <utility>
#include <vector>
#include <tuple>

#include "p2p_handshake.h"
#include "p2p_protocol.h"
#include "p2p_socket.h"
#include <libdevcore/addr_store.h>
#include <libdevcore/config.h>
#include <libdevcore/random.h>
#include <libp2p/handler.h>
#include <networks/network.h>
//#include <libp2p/socket.h>
//#include <libp2p/protocol.h>

#include <boost/asio.hpp>
namespace io = boost::asio;
namespace ip = io::ip;

#define HOST_IDENT std::string

class P2PNodeData
{
public:
    std::shared_ptr<c2pool::dev::coind_config> config;
    std::shared_ptr<io::io_context> context;
    std::shared_ptr<c2pool::Network> net;
    std::shared_ptr<c2pool::dev::AddrStore> addr_store;
    HandlerManagerPtr handler_manager;
public:
    P2PNodeData(std::shared_ptr<io::io_context> _context, auto _net, auto _config, auto _addr_store) : context(std::move(_context)), net(_net), config(_config), addr_store(_addr_store)
    {
        handler_manager = std::make_shared<HandlerManager>();
    }
};

class P2PNodeClient
{
private:
    std::shared_ptr<P2PNodeData> data;

    ip::tcp::resolver resolver;
    io::steady_timer auto_connect_timer;

    const std::chrono::seconds auto_connect_interval{1s};
protected:
    std::map<HOST_IDENT, std::shared_ptr<P2PHandshake>> client_attempts;
    std::set<std::shared_ptr<Protocol>> client_connections;
public:
    P2PNodeClient(std::shared_ptr<P2PNodeData> _data) : data(std::move(_data)), resolver(*data->context), auto_connect_timer(*data->context)  {}

    bool client_connected(std::shared_ptr<Protocol> protocol);

    void auto_connect();

    std::vector<addr_type> get_good_peers(int max_count);
};

class P2PNodeServer
{
private:
    std::shared_ptr<P2PNodeData> data;

    ip::tcp::acceptor acceptor;
protected:
    std::set<std::shared_ptr<P2PHandshake>> server_attempts;
    std::map<HOST_IDENT, int> server_connections;
public:
    P2PNodeServer(std::shared_ptr<P2PNodeData> _data) : data(std::move(_data)), acceptor(*data->context) {}

    bool server_connected(std::shared_ptr<Protocol> protocol)
    {

    }

    void listen()
    {
        acceptor.async_accept([this](boost::system::error_code ec, ip::tcp::socket socket)
                               {
                                   if (!ec)
                                   {
                                       auto _socket = std::make_shared<P2PSocket>(std::move(socket),
                                                                                  data->net);
                                       auto handshake = std::make_shared<P2PHandshake>(_socket, data->handler_manager);
                                       handshake->listen_connection(std::bind(&P2PNodeServer::server_connected, this, std::placeholders::_1));
                                       server_attempts.insert(handshake);
                                   }
                                   else
                                   {
                                       LOG_ERROR << "P2PNode::listen: " << ec.message();
                                   }
                                   listen();
                               });
    }
};

class P2PNode : public std::enable_shared_from_this<P2PNode>, public P2PNodeData, public P2PNodeClient, public P2PNodeServer
{
private:
    std::map<uint64_t, std::shared_ptr<P2PProtocol>> peers;
public:
    P2PNode(std::shared_ptr<io::io_context> _context, std::shared_ptr<c2pool::Network> _net) : P2PNodeData(_context, _net), P2PNodeClient(shared_from_this()), P2PNodeServer(shared_from_this())
    {

    }
};

#undef HOST_IDENT