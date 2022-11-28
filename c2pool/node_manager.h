#pragma once

#include <libnet2/worker.h>
#include <libnet2/coind_node.h>
#include <libnet2/pool_node.h>
#include <libnet2/pool_socket.h>
#include <networks/network.h>
#include <libdevcore/config.h>
#include <libdevcore/addr_store.h>
#include <libp2p/preset/p2p_node_interface.h>
#include <libp2p/node.h>
#include <libcoind/jsonrpc/jsonrpc_coind.h>
#include <libcoind/p2p/coind_socket.h>
#include <libcoind/jsonrpc/stratum_node.h>


class NodeManager : public std::enable_shared_from_this<NodeManager>
{
protected:
    NodeManager()
    {}

public:
    NodeManager(shared_ptr<c2pool::Network> _network, shared_ptr<coind::DigibyteParentNetwork> _parent_network,
                shared_ptr<c2pool::dev::coind_config> _cfg);

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

    shared_ptr<PoolNode> pool_node() const;

    shared_ptr<coind::JSONRPC_Coind> coind() const;

    shared_ptr<CoindNode> coind_node() const;

    shared_ptr<ShareTracker> tracker() const;

//TODO:    shared_ptr<ShareStore> share_store() const;

    shared_ptr<Worker> worker() const;

    shared_ptr<StratumNode> stratum() const;

protected:
    shared_ptr<boost::asio::io_context> _context;
    shared_ptr<c2pool::Network> _net;
    shared_ptr<coind::ParentNetwork> _parent_net;
    shared_ptr<c2pool::dev::coind_config> _config;
    shared_ptr<c2pool::dev::AddrStore> _addr_store;
    shared_ptr<PoolNode> _pool_node;
    shared_ptr<coind::JSONRPC_Coind> _coind;
    shared_ptr<CoindNode> _coind_node;
    shared_ptr<ShareTracker> _tracker;
//TODO:    shared_ptr<ShareStore> _share_store;
    shared_ptr<Worker> _worker;
    shared_ptr<StratumNode> _stratum;

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

    create_set_method(P2PNode, _p2pnode);

    create_set_method(coind::JSONRPC_Coind, _coind);

    create_set_method(CoindNode, _coind_node);

    create_set_method(ShareTracker, _tracker);

    create_set_method(ShareStore, _share_store);
    //TODO: create_set_method(Worker, _worker);
    create_set_method(coind::jsonrpc::StratumNode, _stratum);
};

#undef create_set_method
