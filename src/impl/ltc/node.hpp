#pragma once

#include "config.hpp"
#include "share.hpp"
#include "peer.hpp"
#include "messages.hpp"

#include <pool/node.hpp>
#include <pool/protocol.hpp>
#include <core/message.hpp>
#include <sharechain/prepared_list.hpp>

namespace ltc
{
struct HandleSharesData;

class NodeImpl : public pool::BaseNode<ltc::Config, ltc::ShareChain, ltc::Peer>
{
protected:

    
public:
    NodeImpl() {}
    NodeImpl(boost::asio::io_context* ctx, config_t* config) : base_t(ctx, config) {}

    // INetwork:
    void disconnect() override { }

    // BaseNode:
    void send_ping(peer_ptr peer) override;
    pool::PeerConnectionType handle_version(std::unique_ptr<RawMessage> rmsg, peer_ptr peer) override;
    

    // ltc
    void processing_shares(HandleSharesData& data, NetService addr); // old handle_share
    std::vector<ltc::ShareType> handle_get_share(std::vector<uint256> hashes, uint64_t parents, std::vector<uint256> stops, NetService peer_addr);

};

struct HandleSharesData
{
    std::vector<ShareType> m_items;
    std::map<uint256, std::vector<ltc::MutableTransaction>> m_txs;

    void add(const ShareType& share, std::vector<ltc::MutableTransaction> txs)
    {
        m_items.push_back(share);
        m_txs[share.hash()] = std::move(txs);
    }
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

    ADD_HANDLER(addrs, ltc::message_addrs);
    ADD_HANDLER(addrme, ltc::message_addrme);
    ADD_HANDLER(ping, ltc::message_ping);
    ADD_HANDLER(getaddrs, ltc::message_getaddrs);
    ADD_HANDLER(shares, ltc::message_shares);
    ADD_HANDLER(sharereq, ltc::message_sharereq);
    ADD_HANDLER(sharereply, ltc::message_sharereply);
    ADD_HANDLER(bestblock, ltc::message_bestblock);
    ADD_HANDLER(have_tx, ltc::message_have_tx);
    ADD_HANDLER(losing_tx, ltc::message_losing_tx);
    ADD_HANDLER(remember_tx, ltc::message_remember_tx);
    ADD_HANDLER(forget_tx, ltc::message_forget_tx);
};

class Actual : public pool::Protocol<NodeImpl>
{
public:
    void handle_message(std::unique_ptr<RawMessage> rmsg, NodeImpl::peer_ptr peer) override;

    ADD_HANDLER(addrs, ltc::message_addrs);
    ADD_HANDLER(addrme, ltc::message_addrme);
    ADD_HANDLER(ping, ltc::message_ping);
    ADD_HANDLER(getaddrs, ltc::message_getaddrs);
    ADD_HANDLER(shares, ltc::message_shares);
    ADD_HANDLER(sharereq, ltc::message_sharereq);
    ADD_HANDLER(sharereply, ltc::message_sharereply);
    ADD_HANDLER(bestblock, ltc::message_bestblock);
    ADD_HANDLER(have_tx, ltc::message_have_tx);
    ADD_HANDLER(losing_tx, ltc::message_losing_tx);
    ADD_HANDLER(remember_tx, ltc::message_remember_tx);
    ADD_HANDLER(forget_tx, ltc::message_forget_tx);
};

using Node = pool::NodeBridge<NodeImpl, Legacy, Actual>;

} // namespace ltc
