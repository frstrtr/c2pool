#pragma once

#include <networks/network.h>
#include <devcore/config.h>
#include <memory>

#include <iostream>
using std::shared_ptr;

namespace c2pool::p2p{class P2PNode;}


namespace c2pool::libnet
{
    class NodeManager : public std::enable_shared_from_this<NodeManager>
    {
    public:
        NodeManager(shared_ptr<c2pool::Network> _network, shared_ptr<c2pool::dev::coind_config> _cfg) : _net(_network), _config(_cfg)
        {
        }

        void run();

    public:
        shared_ptr<c2pool::Network> net() const
        {
            return _net;
        }

        shared_ptr<c2pool::dev::coind_config> config() const
        {
            return _config;
        }

    private:
        shared_ptr<c2pool::Network> _net;
        shared_ptr<c2pool::dev::coind_config> _config;
        shared_ptr<c2pool::p2p::P2PNode> p2pnode;
        //TODO:CoindNode
    };
} // namespace c2pool::p2p