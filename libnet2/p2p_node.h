#pragma once

#include <memory>
#include <set>
#include <map>
#include <vector>
#include <tuple>
#include <functional>

#include "p2p_socket.h"
#include "p2p_protocol.h"
#include "p2p_handshake.h"
#include "p2p_node_interface.h"
#include <libp2p/handler.h>
#include <libp2p/node.h>
#include <networks/network.h>
#include <libdevcore/config.h>
#include <libdevcore/addr_store.h>

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

class P2PNodeServer : virtual P2PNodeData
{
protected:
	std::shared_ptr<Listener> listener; // from P2PNode::init()
public:
	P2PNodeServer(std::shared_ptr<io::io_context> _context) : P2PNodeData(std::move(_context)) {}

	void socket_handle(std::shared_ptr<Socket>)
	{
		// TODO:
	}

	void listen()
	{
		(*listener)(std::bind(&P2PNodeServer::socket_handle, this, std::placeholders::_1), std::bind(&P2PNodeServer::listen, this));
	}
};

class P2PNodeClient : virtual P2PNodeData
{
protected:
	std::shared_ptr<Connector> connector; // from P2PNode::init()

	std::map<HOST_IDENT, std::shared_ptr<P2PHandshakeClient>> client_attempts;
	std::set<std::shared_ptr<P2PProtocol>> client_connections;
private:
	io::steady_timer auto_connect_timer;
	const std::chrono::seconds auto_connect_interval{1s};
public:
	P2PNodeClient(std::shared_ptr<io::io_context> _context) : P2PNodeData(std::move(_context)), auto_connect_timer(*context) {}

    void socket_handle(std::shared_ptr<Socket> socket)
    {
        client_attempts[std::get<0>(socket->get_addr())] = std::make_shared<P2PHandshakeClient>(std::move(socket), );
    }

	void auto_connect()
	{
		auto_connect_timer.expires_from_now(auto_connect_interval);
		auto_connect_timer.async_wait([this](boost::system::error_code const &_ec)
									  {
										  if (_ec)
										  {
											  LOG_ERROR << "P2PNode::auto_connect: " << _ec.message();
											  return;
										  }

										  if (!((client_connections.size() < config->desired_conns) &&
												(addr_store->len() > 0) &&
												(client_attempts.size() <= config->max_attempts)))
											  return;

										  for (auto addr: get_good_peers(1))
										  {
											  if (client_attempts.find(std::get<0>(addr)) != client_attempts.end())
											  {
												  //TODO: [UNCOMMENT] LOG_WARNING << "Client already connected to " << std::get<0>(addr) << ":" << std::get<1>(addr) << "!";
												  continue;
											  }

											  auto [ip, port] = addr;
											  LOG_TRACE << "try to connect: " << ip << ":" << port;

											  (*connector)(std::bind(&P2PNodeClient::socket_handle, this, std::placeholders::_1), addr);
										  }
										  auto_connect();
									  });
	}

	std::vector<addr_type> get_good_peers(int max_count);
};

class P2PNode : public virtual P2PNodeData, P2PNodeServer, P2PNodeClient
{
	P2PNode(std::shared_ptr<io::io_context> _context)
			: P2PNodeData(std::move(_context)),
			  P2PNodeServer(context),
			  P2PNodeClient(context)
	{

	}

	template <typename ListenerType, typename ConnectorType>
	void run()
	{
		listener = std::make_shared<ListenerType>();
        listen();
		connector = std::make_shared<ConnectorType>();
        auto_connect();
	}
};