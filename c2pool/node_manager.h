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


class NodeManager : public std::enable_shared_from_this<NodeManager>
{
protected:
    NodeManager()
    {}

public:
    NodeManager(shared_ptr<c2pool::Network> _network, shared_ptr<c2pool::dev::coind_config> _cfg, shared_ptr<WebServer> _web);

    void start()
    {
    }

    // ~NodeManager();

    void run();

    bool is_loaded() const;

public:
    shared_ptr<boost::asio::io_context> context() const;

    shared_ptr<c2pool::Network> net() const;

    shared_ptr<coind::ParentNetwork> parent_net() const;

    shared_ptr<c2pool::dev::coind_config> config() const;

    shared_ptr<c2pool::dev::AddrStore> addr_store() const;

    shared_ptr<PoolNode> pool_node() const;

    shared_ptr<CoindRPC> coind() const;

    shared_ptr<CoindNode> coind_node() const;

    shared_ptr<ShareTracker> tracker() const;

    shared_ptr<Worker> worker() const;

    shared_ptr<StratumNode> stratum() const;

    shared_ptr<WebServer> web_server() const;

protected:
    shared_ptr<boost::asio::io_context> _context;
    shared_ptr<c2pool::Network> _net;
    shared_ptr<coind::ParentNetwork> _parent_net;
    shared_ptr<c2pool::dev::coind_config> _config;
    shared_ptr<c2pool::dev::AddrStore> _addr_store;
    shared_ptr<PoolNode> _pool_node;
    shared_ptr<CoindRPC> _coind;
    shared_ptr<CoindNode> _coind_node;
    shared_ptr<ShareTracker> _tracker;
    shared_ptr<Worker> _worker;
    shared_ptr<StratumNode> _stratum;

    // Общий для всех NodeManager
    shared_ptr<WebServer> _web_server;

private:
    std::atomic<bool> _is_loaded = false;
};


#define create_set_method(type, var_name) \
    void set##var_name(shared_ptr<type> _val)

class TestNodeManager : public NodeManager, public std::enable_shared_from_this<TestNodeManager>
{
public:
    TestNodeManager() : NodeManager()
    {}

public:
    create_set_method(boost::asio::io_context, _context);

    create_set_method(c2pool::Network, _net);

    create_set_method(coind::ParentNetwork, _parent_net);

    create_set_method(c2pool::dev::coind_config, _config);

    create_set_method(c2pool::dev::AddrStore, _addr_store);

    create_set_method(PoolNode, _pool_node);

    create_set_method(CoindRPC, _coind);

    create_set_method(CoindNode, _coind_node);

    create_set_method(ShareTracker, _tracker);

    create_set_method(Worker, _worker);

    create_set_method(StratumNode, _stratum);

    create_set_method(WebServer, _web_server);
};

#undef create_set_method
