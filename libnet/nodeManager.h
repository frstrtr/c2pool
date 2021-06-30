#pragma once

#include <networks/network.h>
#include <devcore/config.h>
#include <devcore/addrStore.h>

#include <coind/jsonrpc/coind.h>

#include <memory>
using std::shared_ptr;

namespace c2pool
{
    namespace libnet
    {
        namespace p2p
        {

            class P2PNode;
        }

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
    public:
        NodeManager(shared_ptr<c2pool::Network> _network, shared_ptr<c2pool::dev::coind_config> _cfg, shared_ptr<c2pool::shares::ShareTracker> _shares_tracker) : _net(_network), _config(_cfg), _tracker(_shares_tracker)
        {
            _addr_store = std::make_shared<c2pool::dev::AddrStore>("data//digibyte//addrs", _network); //TODO: boost::filesystem path
        }

        void run();

    public:
        shared_ptr<c2pool::Network> net() const
        {
            return _net;
        }

        shared_ptr<coind::ParentNetwork> netParent() const
        {
            return _netParent;
        }

        shared_ptr<c2pool::dev::coind_config> config() const
        {
            return _config;
        }

        shared_ptr<c2pool::dev::AddrStore> addr_store() const
        {
            return _addr_store;
        }

        shared_ptr<coind::jsonrpc::Coind> coind() const
        {
            return _coind;
        }

        shared_ptr<c2pool::libnet::p2p::P2PNode> p2pNode() const
        {
            return p2pnode;
        }

        shared_ptr<c2pool::shares::ShareTracker> tracker() const
        {
            return _tracker;
        }

    private:
        shared_ptr<c2pool::Network> _net;
        shared_ptr<coind::ParentNetwork> _netParent; //TODO: init
        shared_ptr<c2pool::dev::coind_config> _config;
        shared_ptr<c2pool::dev::AddrStore> _addr_store;
        shared_ptr<c2pool::libnet::p2p::P2PNode> p2pnode; //start from this
        shared_ptr<coind::jsonrpc::Coind> _coind;
        shared_ptr<c2pool::libnet::CoindNode> coind_node; //TODO: init
        shared_ptr<c2pool::shares::ShareTracker> _tracker;
    };

    class INodeMember
    {
    public:
        const shared_ptr<c2pool::libnet::NodeManager> manager;
        INodeMember(shared_ptr<c2pool::libnet::NodeManager> mng) : manager(mng)
        {
        }

    public:
        shared_ptr<c2pool::Network> net() const
        {
            return manager->net();
        }

        shared_ptr<coind::ParentNetwork> netParent() const
        {
            return manager->netParent();
        }

        shared_ptr<c2pool::dev::coind_config> config() const
        {
            return manager->config();
        }

        shared_ptr<c2pool::dev::AddrStore> addr_store() const
        {
            return manager->addr_store();
        }

        shared_ptr<coind::jsonrpc::Coind> coind() const
        {
            return manager->coind();
        }

        shared_ptr<c2pool::libnet::p2p::P2PNode> p2pNode() const
        {
            return manager->p2pNode();
        }

        shared_ptr<c2pool::shares::ShareTracker> tracker() const
        {
            return manager->tracker();
        }
    };
} // namespace c2pool::libnet