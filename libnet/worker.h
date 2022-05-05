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
}

namespace c2pool::libnet
{
	class Worker
	{
	public:
		Worker(std::shared_ptr<c2pool::Network> net, std::shared_ptr<c2pool::libnet::p2p::P2PNode> p2p_node, std::shared_ptr<ShareTracker> tracker);
		//TODO: return type
		void get_work(uint160 pubkey_hash, uint256 desired_share_target, uint256 desired_pseudoshare_target);

	private:
		std::shared_ptr<c2pool::Network> _net;
		std::shared_ptr<c2pool::libnet::p2p::P2PNode> _p2p_node;
		std::shared_ptr<ShareTracker> _tracker;
	public:
		Variable<Work> current_work;
		double donation_percentage; // TODO: init
	};
}


