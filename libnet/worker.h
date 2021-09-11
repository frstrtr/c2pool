#pragma once

#include <memory>

#include "node_manager.h"
#include <sharechains/tracker.h>
#include <networks/network.h>
#include <coind/jsonrpc/coind.h>

using std::shared_ptr;

namespace c2pool::libnet
{
    class WorkerBridge : public c2pool::libnet::NodeMember
    {
    private:
        shared_ptr<coind::jsonrpc::Coind> _coind;

    public:
        WorkerBridge(shared_ptr<NodeManager> node_manager);

        //TODO: return type
        void get_work();
    };
} // namespace c2pool::libnet::worker
