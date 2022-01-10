#include "node_manager.h"

#include <boost/asio.hpp>

#include <libnet/p2p_node.h>
#include <libnet/coind_node.h>
#include <libnet/worker.h>
#include <libcoind/jsonrpc/jsonrpc_coind.h>
#include <libcoind/jsonrpc/stratum.h>
#include <sharechains/tracker.h>
#include <sharechains/shareStore.h>

using boost::asio::ip::tcp;
using namespace c2pool::shares;

namespace c2pool::libnet
{
    NodeManager::NodeManager(shared_ptr<c2pool::Network> _network, shared_ptr<coind::DigibyteParentNetwork> _parent_network, shared_ptr<c2pool::dev::coind_config> _cfg) : _net(_network), _parent_net(_parent_network), _config(_cfg)
    {
    }

    void NodeManager::run()
    {
        LOG_INFO << "Making asio io_context in NodeManager...";
        _context = make_shared<boost::asio::io_context>(4);

        //0:    COIND
        LOG_INFO << "Init Coind...";
        const char *coind_login = "user:VeryVeryLongPass123"; //TODO: from args
        const char *coind_address = "217.72.4.157"; //TODO: from args
        const char *coind_port = "14024"; //TODO: from args
        _coind = std::make_shared<coind::JSONRPC_Coind>(_context, _parent_net, coind_address, coind_port, coind_login);
        //1:    Determining payout address
        //2:    ShareStore
        LOG_INFO << "ShareStore initialization...";
        _share_store = std::make_shared<c2pool::shares::ShareStore>("dgb"); //TODO: init
        //Init work:
        //3:    ShareTracker
        LOG_INFO << "ShareTracker initialization...";
        _tracker = std::make_shared<ShareTracker>(_net, _parent_net);
        //3.1:  Save shares every 60 seconds
        //TODO: timer in _tracker constructor

        //4:    CoindNode
        LOG_INFO << "CoindNode initialization...";
        _coind_node = std::make_shared<c2pool::libnet::CoindNode>(_context, _parent_net, _coind, _tracker);
        //4.1:  CoindNode.start?
        LOG_INFO << "CoindNode starting...";
        coind_node()->start();
        //...success!

        //Joing c2pool/p2pool network:
        //5:    AddrStore
        _addr_store = std::make_shared<c2pool::dev::AddrStore>("data//digibyte//addrs", _net);
        //5.1:  Bootstrap_addrs
        //5.2:  Parse CLI args for addrs
        //6:    P2PNode
        _p2pnode = std::make_shared<c2pool::libnet::p2p::P2PNode>(_context, _net, _config, _addr_store, _coind_node, _tracker);
        //6.1:  P2PNode.start?
        p2pNode()->start();
        //7:    Save addrs every 60 seconds
        //TODO: timer in _addr_store constructor
        //...success!

        //Start listening for workers with a JSON-RPC server:
        //8:    Worker
        _worker = std::make_shared<c2pool::libnet::WorkerBridge>();
        //9:    Stratum

        //10:   WebRoot
        //...success!
        _is_loaded = true;
        _context->run();
    }

    bool NodeManager::is_loaded() const
    {
        return _is_loaded;
    }

    shared_ptr<boost::asio::io_context> NodeManager::context() const
    {
        return _context;
    }

    shared_ptr<c2pool::Network> NodeManager::net() const
    {
        return _net;
    }

    shared_ptr<coind::ParentNetwork> NodeManager::parent_net() const
    {
        return _parent_net;
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

    shared_ptr<coind::JSONRPC_Coind> NodeManager::coind() const
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

    shared_ptr<c2pool::shares::ShareStore> NodeManager::share_store() const
    {
        return _share_store;
    }

    shared_ptr<c2pool::libnet::WorkerBridge> NodeManager::worker() const
    {
        return _worker;
    }

    shared_ptr<coind::jsonrpc::StratumNode> NodeManager::stratum() const
    {
        return _stratum;
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
    create_set_method(coind::ParentNetwork, _parent_net);
    create_set_method(c2pool::dev::coind_config, _config);
    create_set_method(c2pool::dev::AddrStore, _addr_store);
    create_set_method(c2pool::libnet::p2p::P2PNode, _p2pnode);
    create_set_method(coind::JSONRPC_Coind, _coind);
    create_set_method(c2pool::libnet::CoindNode, _coind_node);
    create_set_method(c2pool::shares::ShareTracker, _tracker);
    create_set_method(c2pool::shares::ShareStore, _share_store);
    create_set_method(c2pool::libnet::WorkerBridge, _worker);
    create_set_method(coind::jsonrpc::StratumNode, _stratum);

#undef create_set_method
}