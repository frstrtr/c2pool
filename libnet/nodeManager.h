#pragma once

#include <networks/network.h>
#include <devcore/config.h>
#include <memory>
#include <devcore/addrStore.h>

#include <iostream>
using std::shared_ptr;

namespace c2pool::libnet::p2p
{
    class P2PNode;
}

namespace c2pool::libnet
{
    class NodeManager : public std::enable_shared_from_this<NodeManager>
    {
    public:
        NodeManager(shared_ptr<c2pool::Network> _network, shared_ptr<c2pool::dev::coind_config> _cfg) : _net(_network), _config(_cfg)
        {
            _addr_store = std::make_shared<c2pool::dev::AddrStore>("data//digibyte//addrs", _network); //TODO: boost::filesystem path
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

        shared_ptr<c2pool::dev::AddrStore> addr_store() const
        {
            return _addr_store;
        }

    private:
        shared_ptr<c2pool::Network> _net;
        shared_ptr<c2pool::dev::coind_config> _config;
        shared_ptr<c2pool::dev::AddrStore> _addr_store;
        shared_ptr<c2pool::libnet::p2p::P2PNode> p2pnode;

        //TODO:CoindNode
    };
} // namespace c2pool::libnet