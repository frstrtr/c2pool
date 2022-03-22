#pragma once

#include <memory>
#include <string>

#include <sharechains/tracker.h>
#include <sharechains/share_types.h>
#include <networks/network.h>
#include <libdevcore/events.h>
#include <btclibs/uint256.h>

using std::shared_ptr;

namespace c2pool{
    namespace libnet::p2p{
        class P2PNode;
    }
}

namespace c2pool::libnet
{
    class Work;

    class WorkerBridge
    {
    private:
        std::shared_ptr<c2pool::Network> _net;
        std::shared_ptr<c2pool::libnet::p2p::P2PNode> _p2p_node;
    public:
        WorkerBridge();

        //TODO: return type
        void get_work();

    private:
        Work compute_work();
    };
} // namespace c2pool::libnet

namespace c2pool::libnet
{
    class Work
    {
        // https://developer.bitcoin.org/reference/block_chain.html#block-headers   
        //    t = dict(
        //            version=bb['version'],
        //            previous_block=bitcoin_data.hash256(bitcoin_data.block_header_type.pack(bb)),
        //            bits=bb['bits'], # not always true
        //            coinbaseflags='',
        //            height=t['height'] + 1,
        //            time=bb['timestamp'] + 600, # better way?
        //            transactions=[],
        //            transaction_fees=[],
        //            merkle_link=bitcoin_data.calculate_merkle_link([None], 0),
        //            subsidy=self.node.net.PARENT.SUBSIDY_FUNC(self.node.bitcoind_work.value['height']),
        //            last_update=self.node.bitcoind_work.value['last_update'],
        //        )

        int32_t version;
        uint256 previous_block;
        uint32_t bits;
        std::string coinfbaseflags;
        int32_t height;
        int32_t timestamp;
        vector<int> transactions; //TODO: TX
        vector<int32_t> transaction_fees; //TODO
        MerkleLink merkle_link;
        int64_t subsidy;
    };
}
