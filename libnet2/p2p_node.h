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
	HandlerManagerPtr<P2PProtocol> handler_manager;

    std::map<uint64_t, std::shared_ptr<P2PProtocol>> peers;
public:
	P2PNodeData(std::shared_ptr<io::io_context> _context) : context(std::move(_context))
	{
		handler_manager = std::make_shared<HandlerManager<P2PProtocol>>();
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

    std::map<std::shared_ptr<Socket>, std::shared_ptr<P2PHandshakeServer>> server_attempts;
    std::map<HOST_IDENT, std::shared_ptr<P2PProtocol>> server_connections;
private:
    std::function<void(std::shared_ptr<P2PHandshake>, std::shared_ptr<net::messages::message_version>)> message_version_handle;
public:
	P2PNodeServer(std::shared_ptr<io::io_context> _context, std::function<void(std::shared_ptr<P2PHandshake>, std::shared_ptr<net::messages::message_version>)> version_handle) : P2PNodeData(std::move(_context)), message_version_handle(version_handle) {}

	void socket_handle(std::shared_ptr<Socket> socket)
	{
		server_attempts[socket] = std::make_shared<P2PHandshakeServer>(std::move(socket),
                                                                       message_version_handle,
                                                                       std::bind(&P2PNodeServer::handshake_handle, this, std::placeholders::_1));
	}

    void handshake_handle(std::shared_ptr<P2PHandshake> _handshake)
    {
        auto _protocol = std::make_shared<P2PProtocol>(context, _handshake->get_socket(), handler_manager, _handshake);
        _protocol->set_handler_manager(handler_manager);

        auto ip = std::get<0>(_protocol->get_socket()->get_addr());
        peers[_protocol->nonce] = _protocol;
        server_connections[ip] = std::move(_protocol);
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
    std::map<HOST_IDENT, std::shared_ptr<P2PProtocol>> client_connections;
private:
	io::steady_timer auto_connect_timer;
	const std::chrono::seconds auto_connect_interval{1s};

    std::function<void(std::shared_ptr<P2PHandshake>, std::shared_ptr<net::messages::message_version>)> message_version_handle;
public:
	P2PNodeClient(std::shared_ptr<io::io_context> _context, std::function<void(std::shared_ptr<P2PHandshake>, std::shared_ptr<net::messages::message_version>)> version_handle) : P2PNodeData(std::move(_context)), message_version_handle(std::move(version_handle)), auto_connect_timer(*context) {}

    void socket_handle(std::shared_ptr<Socket> socket)
    {
        client_attempts[std::get<0>(socket->get_addr())] = std::make_shared<P2PHandshakeClient>(std::move(socket),
                                                                                                message_version_handle,
                                                                                                std::bind(
                                                                                                        &P2PNodeClient::handshake_handle,
                                                                                                        this,
                                                                                                        std::placeholders::_1));
    }

    void handshake_handle(std::shared_ptr<P2PHandshake> _handshake)
    {
        auto _protocol = std::make_shared<P2PProtocol>(context, _handshake->get_socket(), handler_manager, _handshake);
        _protocol->set_handler_manager(handler_manager);

        auto ip = std::get<0>(_protocol->get_socket()->get_addr());
        peers[_protocol->nonce] = _protocol;
        client_connections[ip] = std::move(_protocol);
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
private:
    uint64_t nonce; // node_id
public:
	P2PNode(std::shared_ptr<io::io_context> _context)
			: P2PNodeData(std::move(_context)),
			  P2PNodeServer(context, std::bind(&P2PNode::handle_message_version, this, std::placeholders::_1, std::placeholders::_2)),
			  P2PNodeClient(context, std::bind(&P2PNode::handle_message_version, this, std::placeholders::_1, std::placeholders::_2))
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

    void handle_message_version(std::shared_ptr<P2PHandshake> handshake, std::shared_ptr<net::messages::message_version> msg);

    void handle(std::shared_ptr<net::messages::message_addrs> msg, std::shared_ptr<P2PProtocol> protocol);

    //TODO: test:
    void handle(std::shared_ptr<net::messages::message_addrme> msg, std::shared_ptr<P2PProtocol> protocol);

    void handle(std::shared_ptr<net::messages::message_ping> msg, std::shared_ptr<P2PProtocol> protocol);

    //TODO: TEST
    void handle(std::shared_ptr<net::messages::message_getaddrs> msg, std::shared_ptr<P2PProtocol> protocol);

    void handle(std::shared_ptr<net::messages::message_shares> msg, std::shared_ptr<P2PProtocol> protocol);

    void handle(std::shared_ptr<net::messages::message_sharereq> msg, std::shared_ptr<P2PProtocol> protocol);

    void handle(std::shared_ptr<net::messages::message_sharereply> msg, std::shared_ptr<P2PProtocol> protocol);

    void handle(std::shared_ptr<net::messages::message_bestblock> msg, std::shared_ptr<P2PProtocol> protocol);

    void handle(std::shared_ptr<net::messages::message_have_tx> msg, std::shared_ptr<P2PProtocol> protocol);

    void handle(std::shared_ptr<net::messages::message_losing_tx> msg, std::shared_ptr<P2PProtocol> protocol);

    void handle(std::shared_ptr<net::messages::message_remember_tx> msg, std::shared_ptr<P2PProtocol> protocol);

    void handle(std::shared_ptr<net::messages::message_forget_tx> msg, std::shared_ptr<P2PProtocol> protocol);
};