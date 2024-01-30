#pragma once

#include <libnet/worker.h>
#include <libnet/coind_node.h>
#include <libnet/pool_node.h>
#include <libnet/pool_socket.h>
#include <networks/network.h>
#include <libdevcore/config.h>
#include <libdevcore/addr_store.h>
#include <libp2p/preset/p2p_node_interface.h>
#include <libp2p/node.h>
#include <libcoind/jsonrpc/coindrpc.h>
#include <libcoind/p2p/coind_socket.h>
#include <libcoind/jsonrpc/stratum_node.h>
#include <web_interface/webserver.h>
#include <libp2p/net_supervisor.h>

class NodeManager : public NetSupervisor
{
protected:
    NodeManager() {}
    
    void network_cycle();
public:
    NodeManager(c2pool::Network* _network, c2pool::dev::coind_config* _cfg, WebServer* _web);
    //TODO: ~NodeManager();

    void start() {}
    void run();
    bool is_loaded() const;

public:
    boost::asio::io_context* context() const;
    c2pool::Network* net() const;
    coind::ParentNetwork* parent_net() const;
    c2pool::dev::coind_config* config() const;
    c2pool::dev::AddrStore* addr_store() const;
    PoolNode* pool_node() const;
    CoindRPC* coind_rpc() const;
    CoindNode* coind_node() const;
    ShareTracker* tracker() const;
    Worker* worker() const;
    StratumNode* stratum() const;
    WebServer* web_server() const;

protected:
    boost::asio::io_context* _context;
    c2pool::Network* _net;
    coind::ParentNetwork* _parent_net;
    c2pool::dev::coind_config* _config;
    c2pool::dev::AddrStore* _addr_store;
    PoolNode* _pool_node;
    CoindRPC* _coind_rpc;
    CoindNode* _coind_node;
    ShareTracker* _tracker;
    Worker* _worker;
    StratumNode* _stratum;

    // Общий для всех NodeManager
    WebServer* _web_server;

private:
    std::atomic<bool> _is_loaded = false;
};


#define create_set_method(type, var_name) \
    void set##var_name(type* _val)

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
    create_set_method(PoolNode, _pool_node);
    create_set_method(CoindRPC, _coind_rpc);
    create_set_method(CoindNode, _coind_node);
    create_set_method(ShareTracker, _tracker);
    create_set_method(Worker, _worker);
    create_set_method(StratumNode, _stratum);
    create_set_method(WebServer, _web_server);
};

#undef create_set_method
