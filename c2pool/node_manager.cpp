#include "node_manager.h"

#include <memory>
#include <boost/asio.hpp>
#include <libnet/pool_interface.h>
#include <libnet/coind_interface.h>
#include <libp2p/net_errors.h>

using boost::asio::ip::tcp;
using namespace shares::types;

NodeManager::NodeManager(c2pool::Network* _network, c2pool::dev::coind_config* _cfg, WebServer* _web) 
    : net(_network), parent_net(_network->parent), config(_cfg), web_server(_web)
{
}

void NodeManager::network_cycle()
{
    while (true)
    {
        try 
        {
            LOG_TRACE << "CONTEXT STARTED";
            context->run();
            // break;
        }
        catch (const libp2p::node_exception& ex)
        {
            LOG_ERROR << "Node exception: " << ex.what();
            restart(ex.get_node());
        }

        std::this_thread::sleep_for(std::chrono::seconds(5));
        context->restart();
    }
    LOG_TRACE << "Context finished";
}

void NodeManager::run()
{
    LOG_INFO << "\t\t" << " Making asio io_context in NodeManager...";
    context = new boost::asio::io_context(0);

    // AddrStore
    LOG_INFO << "\t\t" << " AddrStore initialization...";
    addr_store = new c2pool::dev::AddrStore(net->net_name + "/addrs", net);
    // TODO: Bootstrap_addrs
    // TODO: Parse CLI args for addrs
    // TODO: Save addrs every 60 seconds
    //    timer in _addr_store constructor

    // JSONRPC Coind
    LOG_INFO << "\t\t" << " CoindJsonRPC (" << config->coind_ip << ":" << config->jsonrpc_coind_port << "[" << config->jsonrpc_coind_login << "]) initialization...";
    coind_rpc = new CoindRPC(context, parent_net, CoindRPC::rpc_auth_data{config->coind_ip.c_str(), config->jsonrpc_coind_port.c_str()}, config->jsonrpc_coind_login.c_str());
    //TODO remove
    // do {
    //     _coind_rpc->reconnect();
    // } while (!_coind_rpc->check());

    // Determining payout address
    // TODO

    // Share Tracker
    LOG_INFO << "\t\t" << " ShareTracker initialization...";
    tracker = new ShareTracker(net);
    tracker->share_store.legacy_init(c2pool::filesystem::getProjectPath() / "shares.0", [&](auto shares, auto known){tracker->init(shares, known);});
    //TODO: Save shares every 60 seconds
    // timer in _tracker constructor

    // Init Pool Node
    LOG_INFO << "\t\t" << " PoolNode initialization...";
    pool_node = new PoolNode(context);
    pool_node
            ->set_net(net)
            ->set_config(config)
            ->set_addr_store(addr_store)
            ->set_tracker(tracker);
    pool_node->init<PoolListener, PoolConnector>();

    // Init Coind Node
    LOG_INFO << "\t\t" << " CoindNode initialization...";
    coind_node = new CoindNode(context);
    coind_node
            ->set_parent_net(parent_net)
            ->set_coind(coind_rpc)
            ->set_tracker(tracker)
            ->set_pool_node(pool_node);
    coind_node->init<CoindConnector>();

    pool_node->set_coind_node(coind_node); // init coind_node in pool_node

    coind_rpc->add_next_network_layer(coind_node);
    coind_node->add_next_network_layer(pool_node);

    // Worker
    LOG_INFO << "\t\t" << " Worker initialization...";
    worker = new Worker(context, net, pool_node, coind_node, tracker);
    pool_node->add_next_network_layer(worker);

    // Stratum
    LOG_INFO << "\t\t" << " StratumNode initialization...";
    stratum = new StratumNode(context, worker);
    worker->add_next_network_layer(stratum);
    // stratum->listen();

    //...success!
    _is_loaded = true;
    init(context, coind_rpc);
    launch();
    network_cycle();
}

bool NodeManager::is_loaded() const
{
    return _is_loaded;
}