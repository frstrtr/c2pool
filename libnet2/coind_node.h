#pragma once

#include <memory>
#include <map>

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

class CoindNodeData
{
public:
    std::shared_ptr<io::io_context> context;
    std::shared_ptr<coind::ParentNetwork> parent_net;
    std::shared_ptr<ShareTracker> tracker;
    std::shared_ptr<coind::JSONRPC_Coind> coind;
//TODO:    shared_ptr<c2pool::libnet::p2p::P2PNode> _p2p_node;
    HandlerManagerPtr<CoindProtocol> handler_manager;
public:
    coind::TXIDCache txidcache;
    Event<> stop;

    VariableDict<uint256, coind::data::tx_type> known_txs;
    VariableDict<uint256, coind::data::tx_type> mining_txs;
    VariableDict<uint256, coind::data::tx_type> mining2_txs;
    Variable<uint256> best_share;
    Variable<std::vector<std::tuple<std::tuple<std::string, std::string>, uint256>>> desired;

    Event<uint256> new_block;                           //block_hash
    Event<coind::data::tx_type> new_tx;                 //bitcoin_data.tx_type
    Event<std::vector<coind::data::types::BlockHeaderType>> new_headers; //bitcoin_data.block_header_type

    Variable<coind::getwork_result> coind_work;
    Variable<coind::data::BlockHeaderType> best_block_header;
    coind::HeightTracker get_height_rel_highest;

public:
    CoindNodeData(std::shared_ptr<io::io_context> _context) : context(std::move(_context)), get_height_rel_highest(coind, [&](){return coind_work.value().previous_block; })
    {
        handler_manager = std::make_shared<HandlerManager<CoindProtocol>>();
    }

    auto &set_context(std::shared_ptr<io::io_context> _context)
    {
        context = std::move(_context);
        return *this;
    }

    auto &set_parent_net(std::shared_ptr<coind::ParentNetwork> _net)
    {
        parent_net = std::move(_net);
        return *this;
    }

    auto &set_coind(std::shared_ptr<coind::JSONRPC_Coind> _coind)
    {
        coind = std::move(_coind);
        return *this;
    }

    auto &set_tracker(std::shared_ptr<ShareTracker> _tracker)
    {
        tracker = std::move(_tracker);
        return *this;
    }
public:
    void set_best_share();
    void clean_tracker();

    void handle_header(coind::data::BlockHeaderType new_header);
};

class CoindNodeClient : virtual CoindNodeData
{
protected:
    std::shared_ptr<Connector> connector; // from P2PNode::run()

    std::shared_ptr<CoindProtocol> protocol;
public:
    CoindNodeClient(std::shared_ptr<io::io_context> _context) : CoindNodeData(std::move(_context)){}

    //TODO:
//    void socket_handle(std::shared_ptr<Socket> socket)
//    {
//        client_attempts[std::get<0>(socket->get_addr())] = std::make_shared<P2PHandshakeClient>(std::move(socket),
//                                                                                                message_version_handle,
//                                                                                                std::bind(
//                                                                                                        &P2PNodeClient::handshake_handle,
//                                                                                                        this,
//                                                                                                        std::placeholders::_1));
//    }
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
    void work_poller();
    void poll_header();


};