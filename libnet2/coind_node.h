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
		(*connector)(std::bind(&CoindNodeClient::socket_handle, this, std::placeholders::_1), addr);
	}

protected:
    void socket_handle(std::shared_ptr<Socket> socket)
    {
//        client_attempts[std::get<0>(socket->get_addr())] = std::make_shared<P2PHandshakeClient>(std::move(socket),
//                                                                                                message_version_handle,
//                                                                                                std::bind(
//                                                                                                        &P2PNodeClient::handshake_handle,
//                                                                                                        this,
//                                                                                                        std::placeholders::_1));
    }
//
//    void handshake_handle(std::shared_ptr<P2PHandshake> _handshake)
//    {
//        auto _protocol = std::make_shared<P2PProtocol>(context, _handshake->get_socket(), handler_manager, _handshake);
//        _protocol->set_handler_manager(handler_manager);
//
//        auto ip = std::get<0>(_protocol->get_socket()->get_addr());
//        peers[_protocol->nonce] = _protocol;
//        client_connections[ip] = std::move(_protocol);
//    }
};


class CoindNode : public virtual CoindNodeData, CoindNodeClient
{
public:
    CoindNode(std::shared_ptr<io::io_context> _context) : CoindNodeData(std::move(_context)), CoindNodeClient(context),
                                                          work_poller_t(*context)
    {

    }
public:

    void handle(std::shared_ptr<coind::messages::message_version> msg, std::shared_ptr<CoindProtocol> protocol);
    void handle(std::shared_ptr<coind::messages::message_verack> msg, std::shared_ptr<CoindProtocol> protocol);
    void handle(std::shared_ptr<coind::messages::message_ping> msg, std::shared_ptr<CoindProtocol> protocol);
    void handle(std::shared_ptr<coind::messages::message_pong> msg, std::shared_ptr<CoindProtocol> protocol);
    void handle(std::shared_ptr<coind::messages::message_alert> msg, std::shared_ptr<CoindProtocol> protocol);
    void handle(std::shared_ptr<coind::messages::message_getaddr> msg, std::shared_ptr<CoindProtocol> protocol);
    void handle(std::shared_ptr<coind::messages::message_addr> msg, std::shared_ptr<CoindProtocol> protocol);
    void handle(std::shared_ptr<coind::messages::message_inv> msg, std::shared_ptr<CoindProtocol> protocol);
    void handle(std::shared_ptr<coind::messages::message_getdata> msg, std::shared_ptr<CoindProtocol> protocol);
    void handle(std::shared_ptr<coind::messages::message_reject> msg, std::shared_ptr<CoindProtocol> protocol);
    void handle(std::shared_ptr<coind::messages::message_getblocks> msg, std::shared_ptr<CoindProtocol> protocol);
    void handle(std::shared_ptr<coind::messages::message_getheaders> msg, std::shared_ptr<CoindProtocol> protocol);

    void handle(std::shared_ptr<coind::messages::message_tx> msg, std::shared_ptr<CoindProtocol> protocol);
    void handle(std::shared_ptr<coind::messages::message_block> msg, std::shared_ptr<CoindProtocol> protocol);
    void handle(std::shared_ptr<coind::messages::message_headers> msg, std::shared_ptr<CoindProtocol> protocol);
private:
    boost::asio::deadline_timer work_poller_t;

	void start();
    void work_poller();
    void poll_header();


};