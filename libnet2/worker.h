#pragma once

#include <memory>
#include <string>

#include <sharechains/tracker.h>
#include <sharechains/share_types.h>
#include <networks/network.h>
#include <libdevcore/events.h>
#include <btclibs/uint256.h>

using std::shared_ptr;

class CoindNode;
class PoolNode;

namespace coind
{
    class getwork_result;
}

class Work
{
public:
    // https://developer.bitcoin.org/reference/block_chain.html#block-headers
    uint64_t version;
    uint256 previous_block;
    int32_t bits;
    std::vector<unsigned char> coinbaseflags;
    int32_t height;
    int32_t timestamp;
    vector<coind::data::tx_type> transactions;
    vector<int32_t> transaction_fees; //TODO
    coind::data::MerkleLink merkle_link; //TODO
    uint64_t subsidy;
    int32_t last_update;

    static Work from_jsonrpc_data(coind::getwork_result data);

    bool operator==(const Work &value);

    bool operator!=(const Work &value);
};

struct NotifyData
{
    uint64_t version;
    uint256 previous_block;
    coind::data::MerkleLink merkle_link;
    std::vector<unsigned char> coinb1;
	std::vector<unsigned char> coinb2;
    int32_t timestamp;
    int32_t bits;
    uint256 share_target;
};

struct worker_get_work_result
{
    NotifyData ba;
    std::function<bool(coind::data::types::BlockHeaderType, std::string, IntType(64))> get_response;
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

struct user_details
{
    std::string user;
    uint160 pubkey_hash;
    uint256 desired_share_target;
    uint256 desired_pseudoshare_target;
};

class Worker
{
	const int32_t COINBASE_NONCE_LENGTH = 8;
public:
    Worker(std::shared_ptr<c2pool::Network> net, std::shared_ptr<PoolNode> pool_node,
           std::shared_ptr<CoindNode> coind_node, std::shared_ptr<ShareTracker> tracker);

    worker_get_work_result
    get_work(uint160 pubkey_hash, uint256 desired_share_target, uint256 desired_pseudoshare_target);

    local_rates get_local_rates();

    std::map<uint160, uint256> get_local_addr_rates();

    stale_counts get_stale_counts();

    user_details get_user_details(std::string username);

    user_details preprocess_request(std::string username);

private:
    void compute_work();

	uint256 _estimate_local_hash_rate()
	{
		if (recent_shares_ts_work.size() == 50)
		{
			auto hash_rate = std::accumulate(recent_shares_ts_work.begin()+1, recent_shares_ts_work.end(),  uint256::ZERO,
											 [&](const uint256 &x, const std::tuple<int32_t, uint256> &y){
				return x + std::get<1>(y);
			});
			hash_rate = ArithToUint256(UintToArith256(hash_rate) / (std::get<0>(recent_shares_ts_work.back()) - std::get<0>(recent_shares_ts_work.front())));
			if (!hash_rate.IsNull())
				return hash_rate;
		}
		return uint256::ZERO;
	}
public:
    std::shared_ptr<c2pool::Network> _net;
    std::shared_ptr<PoolNode> _pool_node;
    std::shared_ptr<CoindNode> _coind_node;
    std::shared_ptr<ShareTracker> _tracker;

    math::RateMonitor<local_rate_datum> local_rate_monitor;
    math::RateMonitor<local_addr_rate_datum> local_addr_rate_monitor;
public:
    Variable<Work> current_work;
    Event<> new_work;

    //TODO: for web static
    //Event<> share_received;

    std::set<uint256> my_share_hashes;
    std::set<uint256> my_doa_share_hashes;
    std::vector<std::tuple<int32_t, uint256>> recent_shares_ts_work;

    Variable<std::tuple<int32_t, int32_t, int32_t>> removed_unstales;
    Variable<int32_t> removed_doa_unstales;

    double donation_percentage; // TODO: init from args
    double worker_fee; //TODO: init from args
};