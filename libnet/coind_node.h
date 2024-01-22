#pragma once

#include <memory>
#include <map>

#include "coind_node_data.h"
#include <libcoind/height_tracker.h>
#include <libcoind/p2p/coind_protocol.h>
#include <libcoind/p2p/coind_messages.h>
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

class CoindNodeClient : virtual CoindNodeData
{
protected:
    std::unique_ptr<Connector> connector; // from P2PNode::run()

    CoindProtocol* protocol;
public:
    CoindNodeClient(io::io_context* _context, ConnectionStatus* status) : CoindNodeData(_context, status) {}

    void error_handle(const NetAddress& addr, const std::string& err)
    {
        LOG_ERROR << "Coind Client error: " << err;
    }

	void connect(const NetAddress& addr)
	{
		connector->tick(addr);
	}

protected:
    void socket_handle(Socket* socket)
    {
        socket->set_addr();
        LOG_DEBUG_COIND << "CoindNode has been connected to: " << socket;

		protocol = new CoindProtocol(context, socket, handler_manager);
        socket->event_disconnect->subscribe([]()
        {
            LOG_INFO << "COIND DISCONNECTED";
        });

        // start accept messages
        socket->read();
    }
};

#define SET_POOL_DEFAULT_HANDLER(msg) \
	handler_manager->new_handler<coind::messages::message_##msg>(#msg, [&](auto _msg, auto _proto){ handle_message_##msg(_msg, _proto); });

class CoindNode : public virtual CoindNodeData, public SupervisorElement, CoindNodeClient
{
private:
	bool isRunning = false;
public:
    CoindNode(io::io_context* _context) : CoindNodeData(_context, this), CoindNodeClient(context, this), work_poller_t(*context), forget_old_txs_t(*context)
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

        // stop connector
        connector->stop();

        // disconnect protocol
        if (protocol)
        {
            protocol->disconnect("");

            delete protocol;
            protocol = nullptr;
        }

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

        connector = std::make_unique<ConnectorType>(context, parent_net, this);
        connector->init(
                // socket handler
                [&](Socket* socket)
                {
                    socket_handle(socket);
                },
                // error handler
                [&](const NetAddress& addr, const std::string &err)
                {
                    CoindNodeClient::error_handle(addr, err);
                }
        );

        start();
        isRunning = true;
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
    boost::asio::deadline_timer work_poller_t;
	boost::asio::deadline_timer forget_old_txs_t;

	void start();
    void work_poller();
    void poll_header();
	void forget_old_txs();
};
#undef SET_POOL_DEFAULT_HANDLER