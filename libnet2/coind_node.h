#pragma once

#include <memory>
#include <map>

#include "coind_node_data.h"
#include <libcoind/height_tracker.h>
#include <libcoind/p2p/coind_protocol.h>
#include <libcoind/p2p/coind_messages.h>
#include <libcoind/jsonrpc/jsonrpc_coind.h>
#include <libp2p/node.h>
#include <libdevcore/logger.h>
#include <libdevcore/events.h>
#include <networks/network.h>
#include <sharechains/tracker.h>

#include <boost/asio.hpp>
namespace io = boost::asio;
namespace ip = boost::asio::ip;

class CoindNodeClient : virtual CoindNodeData
{
protected:
    std::shared_ptr<Connector> connector; // from P2PNode::run()

    std::shared_ptr<CoindProtocol> protocol;
public:
    CoindNodeClient(std::shared_ptr<io::io_context> _context) : CoindNodeData(std::move(_context)){}

	void connect(std::tuple<std::string, std::string> addr)
	{
		(*connector)([&](std::shared_ptr<Socket> socket){ socket_handle(socket); }, addr);
	}

protected:
    void socket_handle(const std::shared_ptr<Socket>& socket)
    {
        socket->set_addr();
        LOG_DEBUG << "CoindNode has been connected to: " << socket;

		protocol = std::make_shared<CoindProtocol>(context, socket, handler_manager);
    }
};

#define SET_POOL_DEFAULT_HANDLER(msg) \
	handler_manager->new_handler<coind::messages::message_##msg>(#msg, [&](auto _msg, auto _proto){ handle_message_##msg(_msg, _proto); });

class CoindNode : public virtual CoindNodeData, CoindNodeClient
{
private:
	bool isRunning = false;
public:
    CoindNode(std::shared_ptr<io::io_context> _context) : CoindNodeData(std::move(_context)), CoindNodeClient(context),
                                                          work_poller_t(*context)
    {
		SET_POOL_DEFAULT_HANDLER(version);
		SET_POOL_DEFAULT_HANDLER(verack);
		SET_POOL_DEFAULT_HANDLER(ping);
		SET_POOL_DEFAULT_HANDLER(pong);
		SET_POOL_DEFAULT_HANDLER(alert);
		SET_POOL_DEFAULT_HANDLER(getaddr);
		SET_POOL_DEFAULT_HANDLER(addr);
		SET_POOL_DEFAULT_HANDLER(inv);
		SET_POOL_DEFAULT_HANDLER(getdata);
		SET_POOL_DEFAULT_HANDLER(reject);
		SET_POOL_DEFAULT_HANDLER(getblocks);
		SET_POOL_DEFAULT_HANDLER(getheaders);

		SET_POOL_DEFAULT_HANDLER(tx);
		SET_POOL_DEFAULT_HANDLER(block);
		SET_POOL_DEFAULT_HANDLER(headers);
    }

	template <typename ConnectorType>
	void run()
	{
		if (isRunning)
			throw std::runtime_error("CoindNode already running");

		connector = std::make_shared<ConnectorType>(context, parent_net);

		start();
		isRunning = true;
	}
public:

    void handle_message_version(std::shared_ptr<coind::messages::message_version> msg, std::shared_ptr<CoindProtocol> protocol);
    void handle_message_verack(std::shared_ptr<coind::messages::message_verack> msg, std::shared_ptr<CoindProtocol> protocol);
    void handle_message_ping(std::shared_ptr<coind::messages::message_ping> msg, std::shared_ptr<CoindProtocol> protocol);
    void handle_message_pong(std::shared_ptr<coind::messages::message_pong> msg, std::shared_ptr<CoindProtocol> protocol);
    void handle_message_alert(std::shared_ptr<coind::messages::message_alert> msg, std::shared_ptr<CoindProtocol> protocol);
    void handle_message_getaddr(std::shared_ptr<coind::messages::message_getaddr> msg, std::shared_ptr<CoindProtocol> protocol);
    void handle_message_addr(std::shared_ptr<coind::messages::message_addr> msg, std::shared_ptr<CoindProtocol> protocol);
    void handle_message_inv(std::shared_ptr<coind::messages::message_inv> msg, std::shared_ptr<CoindProtocol> protocol);
    void handle_message_getdata(std::shared_ptr<coind::messages::message_getdata> msg, std::shared_ptr<CoindProtocol> protocol);
    void handle_message_reject(std::shared_ptr<coind::messages::message_reject> msg, std::shared_ptr<CoindProtocol> protocol);
    void handle_message_getblocks(std::shared_ptr<coind::messages::message_getblocks> msg, std::shared_ptr<CoindProtocol> protocol);
    void handle_message_getheaders(std::shared_ptr<coind::messages::message_getheaders> msg, std::shared_ptr<CoindProtocol> protocol);

    void handle_message_tx(std::shared_ptr<coind::messages::message_tx> msg, std::shared_ptr<CoindProtocol> protocol);
    void handle_message_block(std::shared_ptr<coind::messages::message_block> msg, std::shared_ptr<CoindProtocol> protocol);
    void handle_message_headers(std::shared_ptr<coind::messages::message_headers> msg, std::shared_ptr<CoindProtocol> protocol);
private:
    boost::asio::deadline_timer work_poller_t;

	void start();
    void work_poller();
    void poll_header();


};
#undef SET_POOL_DEFAULT_HANDLER