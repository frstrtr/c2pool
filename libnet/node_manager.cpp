#include "node_manager.h"

#include <boost/asio.hpp>

#include "p2p_node.h"
#include "coind_node.h"
#include "worker.h"
#include <coind/jsonrpc/coind.h>
#include <sharechains/tracker.h>

using boost::asio::ip::tcp;
using namespace c2pool::shares;

namespace c2pool::libnet
{
    void NodeManager::run()
    {
        _p2pnode = std::make_shared<c2pool::libnet::p2p::P2PNode>(shared_from_this());
        _p2pnode->start();
    }

    shared_ptr<boost::asio::io_context> NodeManager::context() const
    {
        return _context;
    }

    shared_ptr<c2pool::Network> NodeManager::net() const
    {
        return _net;
    }

    shared_ptr<coind::ParentNetwork> NodeManager::netParent() const
    {
        return _netParent;
    }

    shared_ptr<c2pool::dev::coind_config> NodeManager::config() const
    {
        return _config;
    }

    shared_ptr<c2pool::dev::AddrStore> NodeManager::addr_store() const
    {
        return _addr_store;
    }

    shared_ptr<c2pool::libnet::p2p::P2PNode> NodeManager::p2pNode() const
    {
        return _p2pnode;
    }

    shared_ptr<coind::jsonrpc::Coind> NodeManager::coind() const
    {
        return _coind;
    }

    shared_ptr<c2pool::libnet::CoindNode> NodeManager::coind_node() const
    {
        return _coind_node;
    }

    shared_ptr<c2pool::shares::ShareTracker> NodeManager::tracker() const
    {
        return _tracker;
    }

    shared_ptr<c2pool::libnet::WorkerBridge> NodeManager::worker() const
    {
        return _worker;
    }
}

namespace c2pool::libnet
{
#define create_set_method(type, var_name)                      \
    void TestNodeManager::set##var_name(shared_ptr<type> _val) \
    {                                                          \
        var_name = _val;                                       \
    }

    create_set_method(boost::asio::io_context, _context);
    create_set_method(c2pool::Network, _net);
    create_set_method(coind::ParentNetwork, _netParent);
    create_set_method(c2pool::dev::coind_config, _config);
    create_set_method(c2pool::dev::AddrStore, _addr_store);
    create_set_method(c2pool::libnet::p2p::P2PNode, _p2pnode);
    create_set_method(coind::jsonrpc::Coind, _coind);
    create_set_method(c2pool::libnet::CoindNode, _coind_node);
    create_set_method(c2pool::shares::ShareTracker, _tracker);
    create_set_method(c2pool::libnet::WorkerBridge, _worker);

#undef create_set_method
}

namespace c2pool::libnet
{
    NodeMember::NodeMember(shared_ptr<c2pool::libnet::NodeManager> mng) : manager(mng)
    {
    }

    NodeMember::NodeMember(const NodeMember &member) : manager(member.manager)
    {
    }

    shared_ptr<boost::asio::io_context> NodeMember::context() const
    {
        return manager->context();
    }

    shared_ptr<c2pool::Network> NodeMember::net() const
    {
        return manager->net();
    }

    shared_ptr<coind::ParentNetwork> NodeMember::netParent() const
    {
        return manager->netParent();
    }

    shared_ptr<c2pool::dev::coind_config> NodeMember::config() const
    {
        return manager->config();
    }

    shared_ptr<c2pool::libnet::p2p::P2PNode> NodeMember::p2pNode() const
    {
        return manager->p2pNode();
    }

    shared_ptr<c2pool::dev::AddrStore> NodeMember::addr_store() const
    {
        return manager->addr_store();
    }

    shared_ptr<coind::jsonrpc::Coind> NodeMember::coind() const
    {
        return manager->coind();
    }

    shared_ptr<c2pool::libnet::CoindNode> NodeMember::coind_node() const
    {
        return manager->coind_node();
    }

    shared_ptr<c2pool::shares::ShareTracker> NodeMember::tracker() const
    {
        return manager->tracker();
    }

    shared_ptr<c2pool::libnet::WorkerBridge> NodeMember::worker() const
    {
        return manager->worker();
    }

}