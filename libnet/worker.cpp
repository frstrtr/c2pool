#include "worker.h"

#include "node_manager.h"
#include "p2p_node.h"

namespace c2pool::libnet
{
    WorkerBridge::WorkerBridge(shared_ptr<NodeManager> node_manager) : c2pool::libnet::NodeMember(node_manager)
    {
    }

    //TODO: return type
    void WorkerBridge::get_work()
    {
        if (((p2pNode() == nullptr) || p2pNode()->is_connected()) && (net()->PERSIST))
        {
            //TODO: raise jsonrpc.Error_for_code(-12345)(u'p2pool is not connected to any peers')
        }
        // if self.node.best_share_var.value is None and self.node.net.PERSIST:
        //     raise jsonrpc.Error_for_code(-12345)(u'p2pool is downloading shares')

        //TODO: Обработка неизвестных rules, полученных от пира.
        // unknown_rules = set(r[1:] if r.startswith('!') else r for r in self.node.bitcoind_work.value['rules']) - set(getattr(self.node.net, 'SOFTFORKS_REQUIRED', []))
        // if unknown_rules:
        //     print "Unknown softforks found: ", unknown_rules
        //     raise jsonrpc.Error_for_code(-12345)(u'unknown rule activated')
    }
}