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

    struct local_rate_datum
    {
        uint256 work;
        bool dead;
        std::string user; // address
        uint256 share_target;
    };

    struct local_addr_rate_datum
    {
        uint256 work;
        uint160 pubkey_hash;
    };

    struct local_rates
    {
        std::map<std::string, uint256> miner_hash_rates;
        std::map<std::string, uint256> miner_dead_hash_rates;
    };

    struct stale_counts
    {
        std::tuple<int32_t, int32_t> orph_doa; //(orphans; doas)
        int32_t total;
        std::tuple<int32_t, int32_t> recorded_in_chain; // (orphans_recorded_in_chain, doas_recorded_in_chain)
    };
}

namespace c2pool::libnet
{
	class Worker
	{
	public:
		Worker(std::shared_ptr<c2pool::Network> net, std::shared_ptr<c2pool::libnet::p2p::P2PNode> p2p_node, std::shared_ptr<c2pool::libnet::CoindNode> coind_node, std::shared_ptr<ShareTracker> tracker);

        worker_get_work_result get_work(uint160 pubkey_hash, uint256 desired_share_target, uint256 desired_pseudoshare_target);

        local_rates get_local_rates();
        std::map<uint160, uint256> get_local_addr_rates();
        stale_counts get_stale_counts();
	private:
		std::shared_ptr<c2pool::Network> _net;
		std::shared_ptr<c2pool::libnet::p2p::P2PNode> _p2p_node;
        std::shared_ptr<c2pool::libnet::CoindNode> _coind_node;
		std::shared_ptr<ShareTracker> _tracker;

        math::RateMonitor<local_rate_datum> local_rate_monitor;
        math::RateMonitor<local_addr_rate_datum> local_addr_rate_monitor;
	public:
		Variable<Work> current_work;
        Event<> new_work;

        std::set<uint256> my_share_hashes;
        std::set<uint256> my_doa_share_hashes;

        Variable<std::tuple<int32_t, int32_t, int32_t>> removed_unstales; //TODO: WATCH
        Variable<int32_t> removed_doa_unstalel; //TODO: WATCH

		double donation_percentage; // TODO: init
	};
}


