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

    void handle_message_version(std::shared_ptr<P2PHandshake> handshake, std::shared_ptr<net::messages::message_version> msg)
    {
        LOG_DEBUG
            << "handle message_version";
        LOG_INFO << "Peer "
                 << msg->addr_from.address.get()
                 << ":"
                 << msg->addr_from.port.get()
                 << " says protocol version is "
                 << msg->version.get()
                 << ", client version "
                 << msg->sub_version.get();

        if (handshake->other_version.has_value())
        {
            LOG_DEBUG
                << "more than one version message";
        }
        if (msg->version.get() <
            net->MINIMUM_PROTOCOL_VERSION)
        {
            LOG_DEBUG
                << "peer too old";
        }

        handshake->other_version = msg->version.get();
        handshake->other_sub_version = msg->sub_version.get();
        handshake->other_services = msg->services.get();

        if (msg->nonce.get() ==
            nonce)
        {
            LOG_WARNING
                << "was connected to self";
            //TODO: assert
        }

        //detect duplicate in node->peers
        if (peers.find(msg->nonce.get()) !=
            peers.end())
        {

        }
        if (peers.count(
                msg->nonce.get()) != 0)
        {
            auto addr = handshake->get_socket()->get_addr();
            LOG_WARNING
                << "Detected duplicate connection, disconnecting from "
                << std::get<0>(addr)
                << ":"
                << std::get<1>(addr);
            handshake->get_socket()->disconnect();
            return;
        }

        handshake->nonce = msg->nonce.get();
        //TODO: После получения message_version, ожидание сообщения увеличивается с 10 секунд, до 100.
        //*Если сообщение не было получено в течении этого таймера, то происходит дисконект.

//                                                                                                    socket->ping_timer.expires_from_now(
//                                                                                                            boost::asio::chrono::seconds(
//                                                                                                                    (int) c2pool::random::Expovariate(
//                                                                                                                            1.0 /
//                                                                                                                            100)));
//                                                                                                    _socket->ping_timer.async_wait(
//                                                                                                            boost::bind(
//                                                                                                                    &P2P_Protocol::ping_timer_func,
//                                                                                                                    this,
//                                                                                                                    _1));

        //TODO: if (p2p_node->advertise_ip):
        //TODO:     раз в random.expovariate(1/100*len(p2p_node->peers.size()+1), отправляется sendAdvertisement()

        //TODO: msg->best_share_hash != nullptr: p2p_node.handle_share_hashes(...)

        //TODO: <Методы для обработки транзакций>: send_have_tx; send_remember_tx
    }
};