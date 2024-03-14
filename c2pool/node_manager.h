#pragma once

#include <libnet/worker.h>
#include <libnet/coind_node.h>
#include <libnet/pool_node.h>
#include <libnet/pool_socket.h>
#include <networks/network.h>
#include <libdevcore/config.h>
#include <libdevcore/addr_store.h>
#include <libp2p/node.h>
#include <libcoind/jsonrpc/coindrpc.h>
#include <libcoind/jsonrpc/stratum_node.h>
#include <web_interface/webserver.h>
#include <libp2p/network_tree.h>

class NodeManager : private NetworkTree
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
    boost::asio::io_context* context;
    c2pool::Network* net;
    coind::ParentNetwork* parent_net;
    c2pool::dev::coind_config* config;
    c2pool::dev::AddrStore* addr_store;
    PoolNode* pool_node;
    CoindRPC* coind_rpc;
    CoindNode* coind_node;
    ShareTracker* tracker;
    Worker* worker;
    StratumNode* stratum;

    // Общий для всех NodeManager
    WebServer* web_server;

private:
    std::atomic<bool> _is_loaded = false;
};