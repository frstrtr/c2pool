#pragma once

#include <memory>
#include <set>
#include <map>
#include <utility>
#include <vector>
#include <tuple>
#include <functional>

#include "pool_socket.h"
#include "pool_protocol.h"
#include "pool_handshake.h"
#include "pool_node_data.h"
#include <libp2p/handler.h>
#include <libp2p/node.h>

#include <boost/asio.hpp>
namespace io = boost::asio;
namespace ip = io::ip;

#define HOST_IDENT std::string

class PoolNodeServer : virtual PoolNodeData
{
protected:
	std::shared_ptr<Listener> listener; // from P2PNode::run()

    std::map<std::shared_ptr<Socket>, std::shared_ptr<PoolHandshakeServer>> server_attempts;
    std::map<HOST_IDENT, std::shared_ptr<PoolProtocol>> server_connections;
private:
    std::function<void(std::shared_ptr<PoolHandshake>, std::shared_ptr<pool::messages::message_version>)> message_version_handle;
public:
	PoolNodeServer(std::shared_ptr<io::io_context> _context, std::function<void(std::shared_ptr<PoolHandshake>, std::shared_ptr<pool::messages::message_version>)> version_handle) : PoolNodeData(std::move(_context)), message_version_handle(std::move(version_handle)) {}

	void socket_handle(std::shared_ptr<Socket> socket)
	{
		auto _socket = socket;
		server_attempts[_socket] = std::make_shared<PoolHandshakeServer>(std::move(socket),
                                                                        message_version_handle,
                                                                        std::bind(&PoolNodeServer::handshake_handle, this, std::placeholders::_1));
	}

    void handshake_handle(std::shared_ptr<PoolHandshake> _handshake)
    {
		LOG_DEBUG << "Handshake server handle!";
		auto _protocol = std::make_shared<PoolProtocol>(context, _handshake->get_socket(), handler_manager, _handshake);

		auto ip = std::get<0>(_protocol->get_socket()->get_addr());
        peers[_protocol->nonce] = _protocol;
        server_connections[ip] = std::move(_protocol);
    }

	void listen()
	{
		(*listener)(std::bind(&PoolNodeServer::socket_handle, this, std::placeholders::_1), std::bind(&PoolNodeServer::listen, this));
	}
};

class PoolNodeClient : virtual PoolNodeData
{
protected:
	std::shared_ptr<Connector> connector; // from P2PNode::run()

	std::map<HOST_IDENT, std::shared_ptr<PoolHandshakeClient>> client_attempts;
    std::map<HOST_IDENT, std::shared_ptr<PoolProtocol>> client_connections;
private:
	io::steady_timer auto_connect_timer;
	const std::chrono::seconds auto_connect_interval{1s};

    std::function<void(std::shared_ptr<PoolHandshake>, std::shared_ptr<pool::messages::message_version>)> message_version_handle;
public:
	PoolNodeClient(std::shared_ptr<io::io_context> _context, std::function<void(std::shared_ptr<PoolHandshake>, std::shared_ptr<pool::messages::message_version>)> version_handle) : PoolNodeData(std::move(_context)), message_version_handle(std::move(version_handle)), auto_connect_timer(*context) {}

    void socket_handle(std::shared_ptr<Socket> socket)
    {
		auto addr = socket->get_addr();
        client_attempts[std::get<0>(addr)] =
				std::make_shared<PoolHandshakeClient>(std::move(socket),
                                                                                                 message_version_handle,
                                                                                                 std::bind(
                                                                                                        &PoolNodeClient::handshake_handle,
                                                                                                        this,
                                                                                                        std::placeholders::_1));
    }

    void handshake_handle(std::shared_ptr<PoolHandshake> _handshake)
    {
		LOG_DEBUG << "Handshake client handle!";
        auto _protocol = std::make_shared<PoolProtocol>(context, _handshake->get_socket(), handler_manager, _handshake);

        auto ip = std::get<0>(_protocol->get_socket()->get_addr());
        peers[_protocol->nonce] = _protocol;
        client_connections[ip] = std::move(_protocol);
//	TODO:	client_attempts.erase(ip);
    }

	void auto_connect()
	{
		auto_connect_timer.expires_from_now(auto_connect_interval);
		auto_connect_timer.async_wait([this](boost::system::error_code const &_ec)
									  {
//										  LOG_TRACE << "AUTO CONNECT";
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

											  (*connector)(std::bind(&PoolNodeClient::socket_handle, this, std::placeholders::_1), addr);
										  }
						//TODO:				  auto_connect();
									  });
	}

	std::vector<addr_type> get_good_peers(int max_count);
};

#define SET_POOL_DEFAULT_HANDLER(msg) \
	handler_manager->new_handler<pool::messages::message_##msg>(#msg, [&](auto _msg, auto _proto){ handle_message_##msg(_msg, _proto); });

class PoolNode : public virtual PoolNodeData, PoolNodeServer, PoolNodeClient, public enable_shared_from_this<PoolNode>
{
private:
    uint64_t nonce; // node_id

    std::shared_ptr<c2pool::deferred::Fiber> _download_shares_fiber;
public:
	PoolNode(std::shared_ptr<io::io_context> _context)
			: PoolNodeData(std::move(_context)),
              PoolNodeServer(context, std::bind(&PoolNode::handle_message_version, this, std::placeholders::_1, std::placeholders::_2)),
              PoolNodeClient(context, std::bind(&PoolNode::handle_message_version, this, std::placeholders::_1, std::placeholders::_2))
	{
        LOG_INFO << "PoolNode created!";
		SET_POOL_DEFAULT_HANDLER(addrs);
		SET_POOL_DEFAULT_HANDLER(addrme);
		SET_POOL_DEFAULT_HANDLER(ping);
		SET_POOL_DEFAULT_HANDLER(getaddrs);
		SET_POOL_DEFAULT_HANDLER(shares);
		SET_POOL_DEFAULT_HANDLER(sharereq);
		SET_POOL_DEFAULT_HANDLER(sharereply);
		SET_POOL_DEFAULT_HANDLER(bestblock);
		SET_POOL_DEFAULT_HANDLER(have_tx);
		SET_POOL_DEFAULT_HANDLER(losing_tx);
		SET_POOL_DEFAULT_HANDLER(remember_tx);
		SET_POOL_DEFAULT_HANDLER(forget_tx);

        nonce = c2pool::random::randomNonce();
//		handler_manager->new_handler<pool::messages::message_addrs>("addrs", [&](auto msg, auto proto){ handle_message_addrs(msg, proto); });
//		SET_POOL_DEFAULT_HANDLER()
	}

	template <typename ListenerType, typename ConnectorType>
	void run(NodeRunState run_state = both)
	{
		if (run_state == both || run_state == onlyServer)
		{
			listener = std::make_shared<ListenerType>(context, net, config->listenPort);
			listen();
		}

		if (run_state == both || run_state == onlyClient)
		{
			connector = std::make_shared<ConnectorType>(context, net);
			auto_connect();
		}
        start();
	}

	// Handshake handlers
    void handle_message_version(std::shared_ptr<PoolHandshake> handshake, std::shared_ptr<pool::messages::message_version> msg);

	// Pool handlers
    void handle_message_addrs(std::shared_ptr<pool::messages::message_addrs> msg, std::shared_ptr<PoolProtocol> protocol);

    //TODO: test:
    void handle_message_addrme(std::shared_ptr<pool::messages::message_addrme> msg, std::shared_ptr<PoolProtocol> protocol);

    void handle_message_ping(std::shared_ptr<pool::messages::message_ping> msg, std::shared_ptr<PoolProtocol> protocol);

    //TODO: TEST
    void handle_message_getaddrs(std::shared_ptr<pool::messages::message_getaddrs> msg, std::shared_ptr<PoolProtocol> protocol);

    void handle_message_shares(std::shared_ptr<pool::messages::message_shares> msg, std::shared_ptr<PoolProtocol> protocol);

    void handle_message_sharereq(std::shared_ptr<pool::messages::message_sharereq> msg, std::shared_ptr<PoolProtocol> protocol);

    void handle_message_sharereply(std::shared_ptr<pool::messages::message_sharereply> msg, std::shared_ptr<PoolProtocol> protocol);

    void handle_message_bestblock(std::shared_ptr<pool::messages::message_bestblock> msg, std::shared_ptr<PoolProtocol> protocol);

    void handle_message_have_tx(std::shared_ptr<pool::messages::message_have_tx> msg, std::shared_ptr<PoolProtocol> protocol);

    void handle_message_losing_tx(std::shared_ptr<pool::messages::message_losing_tx> msg, std::shared_ptr<PoolProtocol> protocol);

    void handle_message_remember_tx(std::shared_ptr<pool::messages::message_remember_tx> msg, std::shared_ptr<PoolProtocol> protocol);

    void handle_message_forget_tx(std::shared_ptr<pool::messages::message_forget_tx> msg, std::shared_ptr<PoolProtocol> protocol);
private:
    void start();

    void download_shares();
};
#undef SET_POOL_DEFAULT_HANDLER