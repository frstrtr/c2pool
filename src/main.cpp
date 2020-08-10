#include <iostream>
#include "p2p/factory.h"
#include "p2p/p2p.h"
#include "p2p/protocol.h"
#include "boost/asio.hpp"
#include "p2p/node.h"
#include "config.h"
#include "networks/config.h"
#include <memory>

int main(int argc, char* argv[])
{
    c2pool::config::Network* net = new c2pool::config::Network();
    boost::asio::io_context io;

    c2pool::p2p::NodesManager* nodesManager = new c2pool::p2p::NodesManager(io, net);

    //TODO: port 3035
    std::unique_ptr<c2pool::p2p::Node> node = std::make_unique<c2pool::p2p::Node>(nodesManager, 3035);
    
    
    return 0;
}