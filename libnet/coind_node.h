#pragma once

#include <memory>
#include <map>

#include "coind_node_data.h"
#include "coind_protocol.h"
#include "coind_messages.h"

#include <libcoind/height_tracker.h>
#include <libcoind/jsonrpc/coindrpc.h>
#include <libp2p/net_supervisor.h>
#include <libp2p/node.h>
#include <libdevcore/logger.h>
#include <libdevcore/events.h>
#include <networks/network.h>
#include <sharechains/share_tracker.h>

#include <boost/asio.hpp>
namespace io = boost::asio;
namespace ip = boost::asio::ip;

class CoindNodeClient : public Client<BaseCoindSocket>
{
protected:
    CoindNodeData* node_data;
    CoindProtocol* protocol;

public:
    CoindNodeClient(CoindNodeData* node_data_) 
        : Client<BaseCoindSocket>(), node_data(node_data_) {}

	void connect(const NetAddress& addr)
	{
		interface->try_connect(addr);
	}

    void start() override
    {

    }

    void stop() override
    {

    }

    void disconnect(const NetAddress& addr)
    {

    }

protected:
    void error(const libp2p::error& err) override
    {
        throw make_except<coind_exception, NodeExcept>(err.reason);
    }

    void socket_handle(BaseCoindSocket* socket) override
    {
        LOG_DEBUG_COIND << "CoindNode has been connected to: " << socket;

		protocol 
            = new CoindProtocol(
                node_data->context, 
                socket, 
                node_data->handler_manager,
                [&](const libp2p::error& err)
                {
                    error(err);
                }
            );
        socket->event_disconnect->subscribe([]()
        {
            LOG_INFO << "COIND DISCONNECTED";
        });

        // start accept messages
        socket->read();
    }
};

#define SET_COIND_DEFAULT_HANDLER(msg) \
	handler_manager->new_handler<coind::messages::message_##msg, CoindProtocol>(#msg, [&](auto msg_, auto proto_){ handle_message_##msg(msg_, proto_); });

class CoindNode : public virtual CoindNodeData, public NodeExceptionHandler, public SupervisorElement, CoindNodeClient
{
private:
	bool isRunning = false;
public:
    CoindNode(io::io_context* context_) 
        : CoindNodeData(context_, this), CoindNodeClient(this), work_poller_t(context, true), forget_old_txs_t(context, true)
    {
		SET_COIND_DEFAULT_HANDLER(version);
		SET_COIND_DEFAULT_HANDLER(verack);
		SET_COIND_DEFAULT_HANDLER(ping);
		SET_COIND_DEFAULT_HANDLER(pong);
		SET_COIND_DEFAULT_HANDLER(alert);
		SET_COIND_DEFAULT_HANDLER(getaddr);
		SET_COIND_DEFAULT_HANDLER(addr);
		SET_COIND_DEFAULT_HANDLER(inv);
		SET_COIND_DEFAULT_HANDLER(getdata);
		SET_COIND_DEFAULT_HANDLER(reject);
		SET_COIND_DEFAULT_HANDLER(getblocks);
		SET_COIND_DEFAULT_HANDLER(getheaders);

		SET_COIND_DEFAULT_HANDLER(tx);
		SET_COIND_DEFAULT_HANDLER(block);
		SET_COIND_DEFAULT_HANDLER(headers);

        set_send_block([&](const auto &block){
            auto msg = std::make_shared<coind::messages::message_block>(block);
            protocol->write(msg);
        });
    }

    // SupervisorElement
    void stop() override
    {
        if (state == disconnected)
            return;
        
        CoindNodeClient::stop();

        set_state(disconnected);
    }

    void reconnect() override
    {
        connect(NetAddress(parent_net->P2P_ADDRESS, parent_net->P2P_PORT));
        reconnected();
    }

    // Node
	template <typename ConnectorType>
	void run()
    {
        if (isRunning)
            throw std::runtime_error("CoindNode already running");

        CoindNodeClient::init<ConnectorType>(context, parent_net);
        CoindNodeClient::start();

        start();
        isRunning = true;
    }

protected:
    void HandleNodeException() override
	{
		restart();
	}

    void HandleNetException(NetExcept* data) override
	{
		restart();
	}
public:

    void handle_message_version(std::shared_ptr<coind::messages::message_version> msg, CoindProtocol* protocol);
    void handle_message_verack(std::shared_ptr<coind::messages::message_verack> msg, CoindProtocol* protocol);
    void handle_message_ping(std::shared_ptr<coind::messages::message_ping> msg, CoindProtocol* protocol);
    void handle_message_pong(std::shared_ptr<coind::messages::message_pong> msg, CoindProtocol* protocol);
    void handle_message_alert(std::shared_ptr<coind::messages::message_alert> msg, CoindProtocol* protocol);
    void handle_message_getaddr(std::shared_ptr<coind::messages::message_getaddr> msg, CoindProtocol* protocol);
    void handle_message_addr(std::shared_ptr<coind::messages::message_addr> msg, CoindProtocol* protocol);
    void handle_message_inv(std::shared_ptr<coind::messages::message_inv> msg, CoindProtocol* protocol);
    void handle_message_getdata(std::shared_ptr<coind::messages::message_getdata> msg, CoindProtocol* protocol);
    void handle_message_reject(std::shared_ptr<coind::messages::message_reject> msg, CoindProtocol* protocol);
    void handle_message_getblocks(std::shared_ptr<coind::messages::message_getblocks> msg, CoindProtocol* protocol);
    void handle_message_getheaders(std::shared_ptr<coind::messages::message_getheaders> msg, CoindProtocol* protocol);

    void handle_message_tx(std::shared_ptr<coind::messages::message_tx> msg, CoindProtocol* protocol);
    void handle_message_block(std::shared_ptr<coind::messages::message_block> msg, CoindProtocol* protocol);
    void handle_message_headers(std::shared_ptr<coind::messages::message_headers> msg, CoindProtocol* protocol);
private:
    c2pool::Timer work_poller_t;
	c2pool::Timer forget_old_txs_t;

	void start();
    void work_poller();
    void poll_header();
	void forget_old_txs();
};
#undef SET_POOL_DEFAULT_HANDLER