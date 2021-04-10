#pragma once

#include <networks/network.h>
#include <devcore/config.h>
#include <devcore/addrStore.h>

#include <coind/jsonrpc/coind.h>

#include <memory>
using std::shared_ptr;

namespace c2pool
{
    namespace libnet
    {
        namespace p2p
        {

            class P2PNode;
        }

        class CoindNode;
    }

    namespace shares
    {
        namespace tracker
        {
            class ShareTracker;
        }
    }
}

namespace c2pool::libnet
{
    class NodeManager : public std::enable_shared_from_this<NodeManager>
    {
    public:
        NodeManager(shared_ptr<c2pool::Network> _network, shared_ptr<c2pool::dev::coind_config> _cfg, shared_ptr<c2pool::shares::tracker::ShareTracker> _shares_tracker) : _net(_network), _config(_cfg), _tracker(_shares_tracker)
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

        shared_ptr<coind::jsonrpc::Coind> coind() const
        {
            return _coind;
        }

    private:
        shared_ptr<c2pool::Network> _net;
        shared_ptr<c2pool::dev::coind_config> _config;
        shared_ptr<c2pool::dev::AddrStore> _addr_store;
        shared_ptr<c2pool::libnet::p2p::P2PNode> p2pnode;
        shared_ptr<coind::jsonrpc::Coind> _coind;
        shared_ptr<c2pool::libnet::CoindNode> coind_node; //TODO: init
        shared_ptr<c2pool::shares::tracker::ShareTracker> _tracker;
        //TODO: parent[coind] network
    };
} // namespace c2pool::libnet