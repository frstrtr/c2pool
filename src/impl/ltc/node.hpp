#pragma once

#include "peer.hpp"
#include "messages.hpp"

#include <pool/node.hpp>
#include <pool/protocol.hpp>
#include <core/message.hpp>

namespace ltc
{
    
class NodeImpl : public pool::BaseNode<ltc::Peer>
{
    // INetwork:
    void disconnect() override { }

    // BaseNode:
    pool::PeerConnectionType handle_version(std::unique_ptr<RawMessage> rmsg, peer_ptr peer)
    {
        std::cout << "version msg" << std::endl;
        return pool::PeerConnectionType::legacy; 
    }

    NodeImpl() {}
    NodeImpl(boost::asio::io_context* ctx, const std::vector<std::byte>& prefix) : pool::BaseNode<ltc::Peer>(ctx, prefix) {}
};

/*
    void handle_message_addrs(std::shared_ptr<pool::messages::message_addrs> msg, PoolProtocol* protocol);
    void handle_message_addrme(std::shared_ptr<pool::messages::message_addrme> msg, PoolProtocol* protocol);
    void handle_message_ping(std::shared_ptr<pool::messages::message_ping> msg, PoolProtocol* protocol);
    void handle_message_getaddrs(std::shared_ptr<pool::messages::message_getaddrs> msg, PoolProtocol* protocol);
    void handle_message_shares(std::shared_ptr<pool::messages::message_shares> msg, PoolProtocol* protocol);
    void handle_message_sharereq(std::shared_ptr<pool::messages::message_sharereq> msg, PoolProtocol* protocol);
    void handle_message_sharereply(std::shared_ptr<pool::messages::message_sharereply> msg, PoolProtocol* protocol);
    void handle_message_bestblock(std::shared_ptr<pool::messages::message_bestblock> msg, PoolProtocol* protocol);
    void handle_message_have_tx(std::shared_ptr<pool::messages::message_have_tx> msg, PoolProtocol* protocol);
    void handle_message_losing_tx(std::shared_ptr<pool::messages::message_losing_tx> msg, PoolProtocol* protocol);
    void handle_message_remember_tx(std::shared_ptr<pool::messages::message_remember_tx> msg, PoolProtocol* protocol);
    void handle_message_forget_tx(std::shared_ptr<pool::messages::message_forget_tx> msg, PoolProtocol* protocol);
*/

class Legacy : public pool::Protocol<NodeImpl>
{
public:
    void handle_message(std::unique_ptr<RawMessage> rmsg, NodeImpl::peer_ptr peer) override;

    // ADD_HANDLER(addrs, ltc::)
};

class Actual : public pool::Protocol<NodeImpl>
{
public:
    void handle_message(std::unique_ptr<RawMessage> rmsg, NodeImpl::peer_ptr peer) override;
};

using Node = pool::NodeBridge<NodeImpl, Legacy, Actual>;

} // namespace ltc
