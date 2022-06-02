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
#include <libp2p/node.h>
#include <networks/network.h>
//#include <libp2p/socket.h>
//#include <libp2p/protocol.h>

#include <boost/asio.hpp>
namespace io = boost::asio;
namespace ip = io::ip;

#define HOST_IDENT std::string

class P2PListener : public Listener
{
private:
	std::shared_ptr<io::io_context> context;
	ip::tcp::acceptor acceptor;
public:
	P2PListener(auto _context) : context(std::move(_context)), acceptor(*context)
	{
		acceptor.async_accept([this](boost::system::error_code ec, ip::tcp::socket _socket)
							  {
								  if (!ec)
								  {
									  auto socket = std::make_shared<P2PSocket>(std::move(socket),
																				data->net);
									  auto handshake = std::make_shared<P2PHandshake>(socket, data->handler_manager);
									  handshake->listen_connection(std::bind(&P2PNodeServer::server_connected, this, std::placeholders::_1));
									  server_attempts[socket] = handshake;
								  }
								  else
								  {
									  LOG_ERROR << "P2PNode::listen: " << ec.message();
								  }
								  listen();
							  });
	};

	void operator()(std::function<void(std::shared_ptr<Handshake>)> handle)
	{

	}
};

class P2PConnector : public Connector
{
public:

};

class P2PNodeData
{
public:
	std::shared_ptr<c2pool::dev::coind_config> config;
	std::shared_ptr<io::io_context> context;
	std::shared_ptr<c2pool::Network> net;
	std::shared_ptr<c2pool::dev::AddrStore> addr_store;
	HandlerManagerPtr handler_manager;
public:
	P2PNodeData(std::shared_ptr<io::io_context> _context) : context(std::move(_context))
	{
		handler_manager = std::make_shared<HandlerManager>();
	}

	auto &set_context(std::shared_ptr<io::io_context> _context)
	{
		context = std::move(_context);
		return *this;
	}

	auto &set_net(std::shared_ptr<c2pool::Network> _net)
	{
		net = std::move(_net);
		return *this;
	}

	auto &set_config(std::shared_ptr<c2pool::dev::coind_config> _config)
	{
		config = std::move(_config);
		return *this;
	}

	auto &set_net(std::shared_ptr<c2pool::dev::AddrStore> _addr_store)
	{
		addr_store = std::move(_addr_store);
		return *this;
	}
};

class P2PNodeClient : virtual P2PNodeData
{
private:
    ip::tcp::resolver resolver;
    io::steady_timer auto_connect_timer;

    const std::chrono::seconds auto_connect_interval{1s};
protected:
    std::map<HOST_IDENT, std::shared_ptr<P2PHandshake>> client_attempts;
    std::set<std::shared_ptr<Protocol>> client_connections;
public:
    P2PNodeClient(std::shared_ptr<io::io_context> _context) : P2PNodeData(std::move(_context)), resolver(*context), auto_connect_timer(*context)  {}

    bool client_connected(std::shared_ptr<Protocol> protocol);

    void auto_connect();

    std::vector<addr_type> get_good_peers(int max_count);
};

class P2PNodeServer : virtual P2PNodeData
{
private:

protected:
    std::map<std::shared_ptr<Socket>, std::shared_ptr<P2PHandshake>> server_attempts;
    std::map<HOST_IDENT, std::shared_ptr<Protocol>> server_connections;

	std::shared_ptr<Listener>
public:
    P2PNodeServer(std::shared_ptr<io::io_context> _context) : P2PNodeData(std::move(_context)), acceptor(*_context) {}

    bool server_connected(std::shared_ptr<Protocol> protocol);

	template <typename SocketType>
    void listen();
};

class P2PNode : public std::enable_shared_from_this<P2PNode>, public virtual P2PNodeData, public P2PNodeClient, public P2PNodeServer
{
private:
	std::map<uint64_t, std::shared_ptr<P2PProtocol>> peers;
public:
	P2PNode(std::shared_ptr<io::io_context> _context)
			: P2PNodeData(std::move(_context)),
			  P2PNodeClient(context),
			  P2PNodeServer(context)
	{

	}

	template<typename SocketType>
	void run()
	{
		listen <SocketType> ();
		auto_connect();
	}
};

#undef HOST_IDENT