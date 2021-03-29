#pragma once
#include "nodeManager.h"
#include <sharechains/tracker.h>
#include <networks/network.h>
#include <coind/jsonrpc/coind.h>


#include <memory>
using std::shared_ptr;

namespace c2pool::libnet::worker
{
    class WorkerBridge
    {
        private:
            shared_ptr<NodeManager> _node_manager;

            shared_ptr<c2pool::Network> _net; //TODO: parent network
            shared_ptr<c2pool::coind::jsonrpc::Coind> _coind;
        public:
            WorkerBridge(shared_ptr<NodeManager> node_manager){
                _node_manager = node_manager;
                _net = _node_manager->net();
                _coind = _node_manager->coind();
            }
    };
} // namespace c2pool::libnet::worker
