#include <iostream>
#include "p2p/factory.h"
#include "p2p/p2p.h"
#include "p2p/protocol.h"
#include "boost/asio.hpp"
#include "p2p/node.h"
#include "config.h"
#include "networks/config.h"
#include <memory>
#include <console.h>
#include <fstream>

int main(int argc, char* argv[])
{
    c2pool::console::Logger::Init();

    // LOG_TRACE << "A trace severity message" << "TEST";
    // LOG_DEBUG << "A debug severity message";
    // LOG_INFO << "An informational severity message";
    // LOG_WARNING << "A warning severity message";
    // LOG_ERROR << "An error severity message";
    // LOG_FATAL << "A fatal severity message";

    LOG_INFO << "Start c2pool...";

    c2pool::config::Network* net = new c2pool::config::Network();
    boost::asio::io_context io;
    c2pool::p2p::AddrStore addr_store("", net); //TODO: path

    std::shared_ptr<c2pool::p2p::NodesManager> nodesManager = std::make_shared<c2pool::p2p::NodesManager>(io, net);
    
    string port = "3035"; //TODO

    std::unique_ptr<c2pool::p2p::Node> node = std::make_unique<c2pool::p2p::Node>(nodesManager, port, addr_store);
    
    io.run();

    return 0;
}