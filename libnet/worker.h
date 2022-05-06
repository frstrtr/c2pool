#pragma once

#include <memory>
#include <string>

#include <sharechains/tracker.h>
#include <sharechains/share_types.h>
#include <networks/network.h>
#include <libdevcore/events.h>
#include <btclibs/uint256.h>

using std::shared_ptr;

namespace c2pool
{
    namespace libnet
    {
        class CoindNode;
        namespace p2p
        {
            class P2PNode;
        }
    }
}

namespace c2pool::libnet
{
	class Work
	{
	public:
		// https://developer.bitcoin.org/reference/block_chain.html#block-headers
		int32_t version;
		uint256 previous_block;
		uint32_t bits;
		std::string coinfbaseflags;
		int32_t height;
		int32_t timestamp;
		vector<coind::data::tx_type> transactions;
		vector<int32_t> transaction_fees; //TODO
		MerkleLink merkle_link;
		int64_t subsidy;
	};

    struct NotifyData
    {
        int32_t version;
        uint256 previous_block;
        coind::data::MerkleLink merkle_link;
        std::string coinb1;
        std::string coinb2;
        int32_t timestamp;
        uint32_t bits;
        uint256 share_target;
    };

    struct worker_get_work_result
    {
        NotifyData ba;
        std::function<int()> get_response; //TODO: change arguments
    };
}

namespace c2pool::libnet
{
	class Worker
	{
	public:
		Worker(std::shared_ptr<c2pool::Network> net, std::shared_ptr<c2pool::libnet::p2p::P2PNode> p2p_node, std::shared_ptr<c2pool::libnet::CoindNode> coind_node, std::shared_ptr<ShareTracker> tracker);

        worker_get_work_result get_work(uint160 pubkey_hash, uint256 desired_share_target, uint256 desired_pseudoshare_target);

	private:
		std::shared_ptr<c2pool::Network> _net;
		std::shared_ptr<c2pool::libnet::p2p::P2PNode> _p2p_node;
        std::shared_ptr<c2pool::libnet::CoindNode> _coind_node;
		std::shared_ptr<ShareTracker> _tracker;
	public:
		Variable<Work> current_work;
        Event<> new_work;

		double donation_percentage; // TODO: init
	};
}


