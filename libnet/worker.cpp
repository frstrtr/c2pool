#include "worker.h"

#include <vector>

#include "node_manager.h"
#include "p2p_node.h"
#include <btclibs/uint256.h>

using std::vector;

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

        //TODO: [merged mining]
        /*
        if self.merged_work.value:
            tree, size = bitcoin_data.make_auxpow_tree(self.merged_work.value)
            mm_hashes = [self.merged_work.value.get(tree.get(i), dict(hash=0))['hash'] for i in xrange(size)]
            mm_data = '\xfa\xbemm' + bitcoin_data.aux_pow_coinbase_type.pack(dict(
                merkle_root=bitcoin_data.merkle_hash(mm_hashes),
                size=size,
                nonce=0,
            ))
            mm_later = [(aux_work, mm_hashes.index(aux_work['hash']), mm_hashes) for chain_id, aux_work in self.merged_work.value.iteritems()]
        else:
            mm_data = ''
            mm_later = []
        */

        vector<uint256> tx_hashes;
    }

    Work compute_work()
    {
        
    }
}