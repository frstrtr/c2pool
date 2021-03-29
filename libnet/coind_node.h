#pragma once

#include <networks/network.h>
#include <devcore/logger.h>
#include "nodeManager.h"
using c2pool::libnet::NodeManager;

#include <coind/jsonrpc/coind.h>
using namespace c2pool::coind::jsonrpc;

#include <sharechains/tracker.h>
using namespace c2pool::shares::tracker;

#include <memory>
using std::make_shared;
using std::shared_ptr;
//, std::make_shared;

namespace c2pool::libnet
{
    class CoindNode
    {
    public:
    private:
        shared_ptr<Coind> _coind;
        shared_ptr<c2pool::Network> _net;

        shared_ptr<ShareTracker> _tracker; //init + move to NodeManager?
        shared_ptr<NodeManager> _node_manager;

    public:
        CoindNode(shared_ptr<NodeManager> node_manager)
        {
            _node_manager = node_manager;
            _coind = _node_manager->coind();
            _net = _node_manager->net();
        }
    };
}