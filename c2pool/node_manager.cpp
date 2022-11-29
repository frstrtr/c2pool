#include "node_manager.h"

#include <memory>

#include <boost/asio.hpp>

using boost::asio::ip::tcp;
using namespace shares::types;


NodeManager::NodeManager(shared_ptr<c2pool::Network> _network, shared_ptr<coind::DigibyteParentNetwork> _parent_network,
                         shared_ptr<c2pool::dev::coind_config> _cfg) : _net(_network), _parent_net(_parent_network),
                                                                       _config(_cfg)
{
}

void NodeManager::run()
{
    LOG_INFO << "Making asio io_context in NodeManager...";
    _context = std::make_shared<boost::asio::io_context>(0);

    // AddrStore
    _addr_store = std::make_shared<c2pool::dev::AddrStore>("data//digibyte//addrs", _net);
    // TODO: Bootstrap_addrs
    // TODO: Parse CLI args for addrs
    // TODO: Save addrs every 60 seconds
    //    timer in _addr_store constructor

    // JSONRPC Coind
    LOG_INFO << "Init Coind...";
    _coind = std::make_shared<coind::JSONRPC_Coind>(_context, _parent_net, _config->coind_ip.c_str(), _config->jsonrpc_coind_port.c_str(), _config->jsonrpc_coind_login.c_str());

    // Determining payout address
    // TODO

    // Share Store
    // LOG_INFO << "ShareStore initialization...";
    // TODO: _share_store = std::make_shared<ShareStore>("dgb");

    // Share Tracker
    _tracker = std::make_shared<ShareTracker>(_net);
    //TODO: Save shares every 60 seconds
    // timer in _tracker constructor

    // Pool Node
    _pool_node = std::make_shared<PoolNode>(_context);
    _pool_node
            ->set_net(_net)
            ->set_config(_config)
            ->set_addr_store(_addr_store)
            ->set_tracker(_tracker);

    // CoindNode
    _coind_node = std::make_shared<CoindNode>(_context);

    _coind_node
            ->set_parent_net(_parent_net)
            ->set_coind(_coind)
            ->set_tracker(_tracker)
            ->set_pool_node(_pool_node);

    _pool_node->set_coind_node(_coind_node);

    _coind_node->run<CoindConnector<CoindSocket>>();
    _pool_node->run<P2PListener<PoolSocket>, P2PConnector<PoolSocket>>();

    // Worker
    _worker = std::make_shared<Worker>(_net, _pool_node, _coind_node, _tracker);

    // Stratum
    _stratum = std::make_shared<StratumNode>(_context, _worker);
    _stratum->listen();

    // TODO: WebRoot

    //...success!
    _is_loaded = true;
    _context->run();
}

//void NodeManager::run()
//{
//    LOG_INFO << "Making asio io_context in NodeManager...";
//    _context = make_shared<boost::asio::io_context>(4);
//
//    //0:    COIND
//    LOG_INFO << "Init Coind...";
//    _coind = std::make_shared<coind::JSONRPC_Coind>(_context, _parent_net, coind_address, coind_port, coind_login);
//    //1:    Determining payout address
//    //2:    ShareStore
//    LOG_INFO << "ShareStore initialization...";
//    //TODO: init
//    //_share_store = std::make_shared<ShareStore>("dgb"); //TODO: init
//    //Init work:
//    //3:    ShareTracker
//    LOG_INFO << "ShareTracker initialization...";
//    _tracker = std::make_shared<ShareTracker>(_net);
//    //3.1:  Save shares every 60 seconds
//    //TODO: timer in _tracker constructor
//
//    //4:    CoindNode
//    LOG_INFO << "CoindNode initialization...";
//    //TODO: _coind_node = std::make_shared<CoindNode>(_context, _parent_net, _coind, _tracker);
//    //4.1:  CoindNode.start?
//    LOG_INFO << "CoindNode starting...";
//    //TODO: coind_node()->start();
//    //...success!
//
//    //Joing c2pool/p2pool network:
//    //5:    AddrStore
//    _addr_store = std::make_shared<c2pool::dev::AddrStore>("data//digibyte//addrs", _net);
//    //5.1:  Bootstrap_addrs
//    //5.2:  Parse CLI args for addrs
//    //6:    P2PNode
////        TODO:_p2pnode = std::make_shared<P2PNode>(_context, _net, _config, _addr_store, _coind_node, _tracker);
//    //6.1:  P2PNode.start?
//    //TODO: p2pNode()->start();
//    //7:    Save addrs every 60 seconds
//    //TODO: timer in _addr_store constructor
//    //...success!
//
//    //Start listening for workers with a JSON-RPC server:
//    //8:    Worker
////TODO:        _worker = std::make_shared<c2pool::libnet::Worker>(_net, _p2pnode, _coind_node, _tracker);
//    //9:    Stratum
//
//    //10:   WebRoot
//    //...success!
//    _is_loaded = true;
//    _context->run();
//}

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

shared_ptr<PoolNode> NodeManager::pool_node() const
{
    return _pool_node;
}

shared_ptr<coind::JSONRPC_Coind> NodeManager::coind() const
{
    return _coind;
}

shared_ptr<CoindNode> NodeManager::coind_node() const
{
    return _coind_node;
}

shared_ptr<ShareTracker> NodeManager::tracker() const
{
    return _tracker;
}

//shared_ptr<ShareStore> NodeManager::share_store() const
//{
//    return _share_store;
//}

shared_ptr<Worker> NodeManager::worker() const
{
    return _worker;
}

shared_ptr<StratumNode> NodeManager::stratum() const
{
    return _stratum;
}


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

create_set_method(PoolNode, _pool_node);

create_set_method(coind::JSONRPC_Coind, _coind);

create_set_method(CoindNode, _coind_node);

create_set_method(ShareTracker, _tracker);

//create_set_method(ShareStore, _share_store);

create_set_method(Worker, _worker);

create_set_method(StratumNode, _stratum);

#undef create_set_method
