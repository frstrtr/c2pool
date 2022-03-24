#pragma once

#include <memory>
#include <networks/network.h>
#include <libdevcore/config.h>
#include <libdevcore/addrStore.h>
#include <boost/asio/io_context.hpp>

using std::shared_ptr;

class ShareTracker;
class ShareStore;

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


}
namespace coind
{
    class JSONRPC_Coind;
    namespace jsonrpc
    {
        class StratumNode;
    }
}

namespace c2pool::libnet
{
    class NodeManager : public std::enable_shared_from_this<NodeManager>
    {
    protected:
        NodeManager() {}

    public:
        NodeManager(shared_ptr<c2pool::Network> _network,  shared_ptr<coind::DigibyteParentNetwork> _parent_network, shared_ptr<c2pool::dev::coind_config> _cfg);

        void start()
        {
        }

        //TODO: ~NodeManager();

        void run();

        bool is_loaded() const;

    public:
        shared_ptr<boost::asio::io_context> context() const;
        shared_ptr<c2pool::Network> net() const;
        shared_ptr<coind::ParentNetwork> parent_net() const;
        shared_ptr<c2pool::dev::coind_config> config() const;
        shared_ptr<c2pool::dev::AddrStore> addr_store() const;
        shared_ptr<c2pool::libnet::p2p::P2PNode> p2pNode() const;
        shared_ptr<coind::JSONRPC_Coind> coind() const;
        shared_ptr<c2pool::libnet::CoindNode> coind_node() const;
        shared_ptr<ShareTracker> tracker() const;
        shared_ptr<ShareStore> share_store() const;
        shared_ptr<c2pool::libnet::WorkerBridge> worker() const;
        shared_ptr<coind::jsonrpc::StratumNode> stratum() const;

    protected:
        shared_ptr<boost::asio::io_context> _context;
        shared_ptr<c2pool::Network> _net;
        shared_ptr<coind::ParentNetwork> _parent_net;
        shared_ptr<c2pool::dev::coind_config> _config;
        shared_ptr<c2pool::dev::AddrStore> _addr_store;
        shared_ptr<c2pool::libnet::p2p::P2PNode> _p2pnode;
        shared_ptr<coind::JSONRPC_Coind> _coind;
        shared_ptr<c2pool::libnet::CoindNode> _coind_node;
        shared_ptr<ShareTracker> _tracker;
        shared_ptr<ShareStore> _share_store;
        shared_ptr<c2pool::libnet::WorkerBridge> _worker;
        shared_ptr<coind::jsonrpc::StratumNode> _stratum;

    private:
        std::atomic<bool> _is_loaded = false;
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
        create_set_method(boost::asio::io_context, _context);
        create_set_method(c2pool::Network, _net);
        create_set_method(coind::ParentNetwork, _parent_net);
        create_set_method(c2pool::dev::coind_config, _config);
        create_set_method(c2pool::dev::AddrStore, _addr_store);
        create_set_method(c2pool::libnet::p2p::P2PNode, _p2pnode);
        create_set_method(coind::JSONRPC_Coind, _coind);
        create_set_method(c2pool::libnet::CoindNode, _coind_node);
        create_set_method(ShareTracker, _tracker);
        create_set_method(ShareStore, _share_store);
        create_set_method(c2pool::libnet::WorkerBridge, _worker);
        create_set_method(coind::jsonrpc::StratumNode, _stratum);
    };
#undef create_set_method
} // namespace c2pool::libnet