#pragma once

#include <memory>
#include <networks/network.h>
#include <devcore/config.h>
#include <devcore/addrStore.h>

using std::shared_ptr;

namespace c2pool
{
    namespace libnet
    {
        namespace p2p
        {
            class P2PNode;
        }
        class WorkerBridge;
        class CoindNode;
    }

    namespace shares
    {
        class ShareTracker;
    }
}

namespace c2pool::libnet
{
    class NodeManager : public std::enable_shared_from_this<NodeManager>
    {
    protected:
        NodeManager() {}

    public:
        NodeManager(shared_ptr<c2pool::Network> _network, shared_ptr<c2pool::dev::coind_config> _cfg) : _net(_network), _config(_cfg)
        {
            _addr_store = std::make_shared<c2pool::dev::AddrStore>("data//digibyte//addrs", _network); //TODO: boost::filesystem path
        }

        void run();

    public:
        shared_ptr<c2pool::Network> net() const;
        shared_ptr<coind::ParentNetwork> netParent() const;
        shared_ptr<c2pool::dev::coind_config> config() const;
        shared_ptr<c2pool::dev::AddrStore> addr_store() const;
        shared_ptr<c2pool::libnet::p2p::P2PNode> p2pNode() const;
        shared_ptr<coind::jsonrpc::Coind> coind() const;
        shared_ptr<c2pool::libnet::CoindNode> coind_node() const;
        shared_ptr<c2pool::shares::ShareTracker> tracker() const;
        shared_ptr<c2pool::libnet::WorkerBridge> worker() const;

    protected:
        shared_ptr<c2pool::Network> _net;
        shared_ptr<coind::ParentNetwork> _netParent; //TODO: init
        shared_ptr<c2pool::dev::coind_config> _config;
        shared_ptr<c2pool::dev::AddrStore> _addr_store;
        shared_ptr<c2pool::libnet::p2p::P2PNode> _p2pnode; //start from this
        shared_ptr<coind::jsonrpc::Coind> _coind;
        shared_ptr<c2pool::libnet::CoindNode> _coind_node; //TODO: init
        shared_ptr<c2pool::shares::ShareTracker> _tracker;
        shared_ptr<c2pool::libnet::WorkerBridge> _worker; //TODO: init
    };
} // namespace c2pool::libnet

namespace c2pool::libnet
{
#define create_set_method(type, var_name) \
    void set##var_name(shared_ptr<type> _val)

    class TestNodeManager : public NodeManager, public std::enable_shared_from_this<TestNodeManager>
    {
    public:
        TestNodeManager() : NodeManager() {}

    public:
        create_set_method(c2pool::Network, _net);
        create_set_method(coind::ParentNetwork, _netParent);
        create_set_method(c2pool::dev::coind_config, _config);
        create_set_method(c2pool::dev::AddrStore, _addr_store);
        create_set_method(c2pool::libnet::p2p::P2PNode, _p2pnode);
        create_set_method(coind::jsonrpc::Coind, _coind);
        create_set_method(c2pool::libnet::CoindNode, _coind_node);
        create_set_method(c2pool::shares::ShareTracker, _tracker);
        create_set_method(c2pool::libnet::WorkerBridge, _worker);
    };
#undef create_set_method
} // namespace c2pool::libnet

namespace c2pool::libnet
{
    class NodeMember
    {
    public:
        const shared_ptr<c2pool::libnet::NodeManager> manager;

        NodeMember(shared_ptr<c2pool::libnet::NodeManager> mng);
        NodeMember(const NodeMember &member);

    public:
        shared_ptr<c2pool::Network> net() const;

        shared_ptr<coind::ParentNetwork> netParent() const;

        shared_ptr<c2pool::dev::coind_config> config() const;

        shared_ptr<c2pool::dev::AddrStore> addr_store() const;
        shared_ptr<c2pool::libnet::p2p::P2PNode> p2pNode() const;

        shared_ptr<coind::jsonrpc::Coind> coind() const;

        shared_ptr<c2pool::libnet::CoindNode> coind_node() const; //

        shared_ptr<c2pool::shares::ShareTracker> tracker() const;
        shared_ptr<c2pool::libnet::WorkerBridge> worker() const; //
    };
} // namespace c2pool::libnet