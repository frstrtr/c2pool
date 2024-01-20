#include "node_manager.h"

#include <memory>
#include <boost/asio.hpp>

using boost::asio::ip::tcp;
using namespace shares::types;


NodeManager::NodeManager(c2pool::Network* _network, c2pool::dev::coind_config* _cfg, WebServer* _web) : _net(_network), _parent_net(_network->parent), _config(_cfg), _web_server(_web)
{
}

void NodeManager::run()
{
    LOG_INFO << "Making asio io_context in NodeManager...";
    _context = new boost::asio::io_context(0);

    // AddrStore
    _addr_store = new c2pool::dev::AddrStore(_net->net_name + "/addrs", _net);
    // TODO: Bootstrap_addrs
    // TODO: Parse CLI args for addrs
    // TODO: Save addrs every 60 seconds
    //    timer in _addr_store constructor

    // JSONRPC Coind
    LOG_INFO << "Init Coind (" << _config->coind_ip << ":" << _config->jsonrpc_coind_port << "[" << _config->jsonrpc_coind_login << "])...";
    
    _coind = new CoindRPC(_context, _parent_net, CoindRPC::rpc_auth_data{_config->coind_ip.c_str(), _config->jsonrpc_coind_port.c_str()}, _config->jsonrpc_coind_login.c_str());
    add(_coind, 0);
    do {
        _coind->reconnect();
    } while (!_coind->check());

    // Determining payout address
    // TODO

    // Share Tracker
    _tracker = new ShareTracker(_net);
    _tracker->share_store.legacy_init(c2pool::filesystem::getProjectPath() / "shares.0", [&](auto shares, auto known){_tracker->init(shares, known);});
    //TODO: Save shares every 60 seconds
    // timer in _tracker constructor

    // Pool Node
    _pool_node = new PoolNode(_context);
    _pool_node
            ->set_net(_net)
            ->set_config(_config)
            ->set_addr_store(_addr_store)
            ->set_tracker(_tracker);

    // CoindNode
    _coind_node = new CoindNode(_context);
    add(_coind_node, 1);

    _coind_node
            ->set_parent_net(_parent_net)
            ->set_coind(_coind)
            ->set_tracker(_tracker)
            ->set_pool_node(_pool_node);

    _pool_node->set_coind_node(_coind_node);

    _coind_node->run<CoindConnector<CoindSocket>>();
    _pool_node->run<P2PListener<PoolSocket>, P2PConnector<PoolSocket>>();

    // Worker
    _worker = new Worker(_net, _pool_node, _coind_node, _tracker);

    // Stratum
    _stratum = new StratumNode(_context, _worker);
    _stratum->listen();

    //...success!
    _is_loaded = true;
    _context->run();
}

bool NodeManager::is_loaded() const
{
    return _is_loaded;
}

boost::asio::io_context* NodeManager::context() const
{
    return _context;
}

c2pool::Network* NodeManager::net() const
{
    return _net;
}

coind::ParentNetwork* NodeManager::parent_net() const
{
    return _parent_net;
}

c2pool::dev::coind_config* NodeManager::config() const
{
    return _config;
}

c2pool::dev::AddrStore* NodeManager::addr_store() const
{
    return _addr_store;
}

PoolNode* NodeManager::pool_node() const
{
    return _pool_node;
}

CoindRPC* NodeManager::coind() const
{
    return _coind;
}

CoindNode* NodeManager::coind_node() const
{
    return _coind_node;
}

ShareTracker* NodeManager::tracker() const
{
    return _tracker;
}

//ShareStore* NodeManager::share_store() const
//{
//    return _share_store;
//}

Worker* NodeManager::worker() const
{
    return _worker;
}

StratumNode* NodeManager::stratum() const
{
    return _stratum;
}

WebServer* NodeManager::web_server() const
{
    return _web_server;
}


#define create_set_method(type, var_name)                      \
    void TestNodeManager::set##var_name(type* _val)            \
    {                                                          \
        var_name = _val;                                       \
    }

create_set_method(boost::asio::io_context, _context);
create_set_method(c2pool::Network, _net);
create_set_method(coind::ParentNetwork, _parent_net);
create_set_method(c2pool::dev::coind_config, _config);
create_set_method(c2pool::dev::AddrStore, _addr_store);
create_set_method(PoolNode, _pool_node);
create_set_method(CoindRPC, _coind);
create_set_method(CoindNode, _coind_node);
create_set_method(ShareTracker, _tracker);
//create_set_method(ShareStore, _share_store);
create_set_method(Worker, _worker);
create_set_method(StratumNode, _stratum);
create_set_method(WebServer, _web_server)

#undef create_set_method
