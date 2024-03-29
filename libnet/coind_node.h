#pragma once

#include <memory>
#include <map>

#include "coind_network.h"
#include "coind_node_data.h"
#include "coind_messages.h"

#include <libcoind/height_tracker.h>
#include <libcoind/jsonrpc/coindrpc.h>
#include <libp2p/node.h>
#include <libdevcore/logger.h>
#include <libdevcore/events.h>
#include <networks/network.h>
#include <sharechains/share_tracker.h>

#include <boost/asio.hpp>
namespace io = boost::asio;
namespace ip = boost::asio::ip;

#define SET_COIND_DEFAULT_HANDLER(msg) \
	handler_manager->new_handler<coind::messages::message_##msg, CoindProtocol>(#msg, [&](auto msg_, auto proto_){ handle_message_##msg(msg_, proto_); });

class CoindNode : public CoindNodeData, CoindNodeClient
{
public:
    CoindNode(io::io_context* context_) 
        : CoindNodeData(context_), CoindNodeClient(this), work_poller_t(context, true), forget_old_txs_t(context, true)
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

	template <typename ConnectorType>
	void init()
    {
        CoindNodeClient::init<ConnectorType>(context, parent_net);
    }

    void run() override
    {
        LOG_INFO << "CoindNode running...";

        CoindNodeClient::start();
        CoindNode::start();
        connect(NetAddress(parent_net->P2P_ADDRESS, parent_net->P2P_PORT));
    }

    void stop() override
    {
        LOG_INFO << "CoindNode stopping...!";
        CoindNodeClient::stop();
        LOG_INFO << "...CoindNode stopped!";
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