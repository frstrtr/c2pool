#pragma once

#include <map>
#include <set>
#include <memory>
#include <numeric>
#include <functional>

#include "p2p_handshake.h"
#include "p2p_protocol.h"
#include "p2p_socket.h"
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
    std::shared_ptr<io::io_context> context;
    std::shared_ptr<c2pool::Network> net;
    HandlerManager handler_manager;
public:
    P2PNodeData(std::shared_ptr<io::io_context> _context, auto _net) : context(_context), net(_net)
    {

    }
};

class P2PNodeClient
{
private:
    std::shared_ptr<P2PNodeData> data;

    ip::tcp::resolver resolver;
protected:
    std::map<HOST_IDENT, std::shared_ptr<P2PSocket>> client_attempts;
    std::set<std::shared_ptr<P2PProtocol>> client_connections;
public:
    P2PNodeClient(std::shared_ptr<P2PNodeData> _data) : data(_data), resolver(*data->context)  {}

    bool client_connected(std::shared_ptr<Protocol> protocol)
    {

    }

    void auto_connect()
    {

    }
};

class P2PNodeServer
{
private:
    std::shared_ptr<P2PNodeData> data;

    ip::tcp::acceptor acceptor;
protected:
    std::set<std::shared_ptr<P2PSocket>> server_attempts;
    std::map<HOST_IDENT, int> server_connections;
public:
    P2PNodeServer(std::shared_ptr<P2PNodeData> _data) : data(_data), acceptor(*data->context) {}

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
                                                                                  [&](std::shared_ptr<RawMessage> raw_msg)
                                                                                  {

                                                                                  },
                                                                                  data->net);
                                       server_attempts.insert(_socket);
                                       _socket->init(std::bind(&P2PNodeServer::server_connected, this, std::placeholders::_1));
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