#pragma once

#include <map>
#include <vector>
#include <string>
#include <memory>
#include <set>
#include <tuple>
using namespace std;

#include "univalue.h"
#include "share.h"
#include "share_adapters.h"
#include "prefsum_share2.h"
#include <btclibs/uint256.h>
#include <btclibs/arith_uint256.h>
#include <libcoind/data.h>
#include <libcoind/transaction.h>
#include <libdevcore/logger.h>
#include <libdevcore/common.h>
#include <libdevcore/events.h>
#include <networks/network.h>
using namespace shares;

class Share;
class GeneratedShare;

#define LOOKBEHIND 200
//TODO: multi_index for more speed https://www.boost.org/doc/libs/1_76_0/libs/multi_index/doc/index.html

struct desired_type
{
    std::tuple<std::string, std::string> peer_addr;
    uint256 hash;
    uint32_t timestamp;
    uint256 target;

    friend bool operator<(const desired_type& l, const desired_type& r)
    {
        return std::tie(l.peer_addr, l.hash, l.target, l.timestamp) < std::tie(r.peer_addr, r.hash, r.target, r.timestamp);
    }
};

struct TrackerThinkResult
{
	uint256 best;
	std::vector<std::tuple<std::tuple<std::string, std::string>, uint256>> desired;
    std::vector<std::tuple<std::tuple<uint256, int32_t, int32_t>, uint256>> decorated_heads;
	std::set<std::tuple<std::string, std::string>> bad_peer_addresses;
};

class ShareTracker : public SharePrefsum2, public enable_shared_from_this<ShareTracker>
{
public:
    VerifiedSharePrefsum2 verified;
    Event<ShareType> removed;
public:
	shared_ptr<c2pool::Network> net;
	shared_ptr<coind::ParentNetwork> parent_net;
public:
	ShareTracker(shared_ptr<c2pool::Network> _net);

	ShareType get(uint256 hash);

	void add(ShareType share) override;
    void remove(uint256 hash) override;

	bool attempt_verify(ShareType share);

	TrackerThinkResult think(boost::function<int32_t(uint256)> block_rel_height_func, uint256 previous_block, uint32_t bits, std::map<uint256, coind::data::tx_type> known_txs);

	arith_uint256 get_pool_attempts_per_second(uint256 previous_share_hash, int32_t dist, bool min_work = false);

	std::tuple<int32_t, uint256> score(uint256 share_hash, boost::function<int32_t(uint256)> block_rel_height_func)
	{
		uint256 score_res;
		score_res.SetNull();
		auto head_height = verified.get_height(share_hash);
		if (head_height < net->CHAIN_LENGTH)
		{
			return std::make_tuple(head_height, score_res);
		}

		auto end_point = verified.get_nth_parent_key(share_hash, net->CHAIN_LENGTH * 15 / 16);

		std::optional<int32_t> block_height;
		auto gen_verif_chain = verified.get_chain(end_point, net->CHAIN_LENGTH / 16);

		uint256 hash;
		while (gen_verif_chain(hash))
		{
			auto share = verified.items[hash];

			auto block_height_temp = block_rel_height_func(share->header->previous_block);
			if (!block_height.has_value())
			{
				block_height = block_height_temp;
			} else
			{
				if (block_height.value() > block_height_temp)
				{
					block_height = block_height_temp;
				}
			}
		}

		score_res = ArithToUint256(verified.get_sum(share_hash, end_point).work /
								   ((-block_height.value() + 1) * parent_net->BLOCK_PERIOD));
		return std::make_tuple(net->CHAIN_LENGTH, score_res);
	}

    std::map<uint64_t, uint256> get_desired_version_counts(uint256 best_share_hash, uint64_t dist)
    {
        std::map<uint64_t, arith_uint256> _result;

        auto get_chain_func = get_chain(best_share_hash, dist);
        uint256 hash;

        while(get_chain_func(hash))
        {
            auto share = get(hash);

            if (_result.find(*share->desired_version) == _result.end())
                _result[*share->desired_version] = 0;

            _result[*share->desired_version] += UintToArith256(coind::data::target_to_average_attempts(share->target)) + 1;
        }

        std::map<uint64_t, uint256> result;
        for (auto v : _result)
        {
            result[v.first] = ArithToUint256(v.second);
        }
        return result;
    }

	//TODO: test!
	std::tuple<std::map<std::vector<unsigned char>, arith_uint256>, arith_uint256, arith_uint256>
	        get_cumulative_weights(uint256 start, int32_t max_shares, arith_uint256 desired_weight)
	{
		// [last; best]
		auto best = get_sum_to_last(start);
		auto p = best.weight.total_weight - desired_weight;


		auto it = sum.find(start);

		while (it != sum.end())
		{
			if (it->second.weight.total_weight <= p)
				break;

			if ((best.height - it->second.height) == max_shares)
				break;

			it = it->second.prev;
		}

		element_type i;
		if (it != sum.end())
		{
			if (it->second.weight.total_weight < p)
			{
				element_type x;
				if (it->second.prev != sum.end())
				{
					x = get_sum(it->first, it->second.prev->first);
				} else
				{
					x = get_sum_to_last(it->first);
				}

				auto cur = get_sum(start, it->first);
				auto script = x.weight.weights->amount.first;
				// - new_weights = {script: (desired_weight - total_weight1)//65535*weights2[script]//(total_weight2//65535)}
				auto new_weight = (desired_weight - cur.weight.total_weight)/65535*x.weight.weights->amount.second/(cur.weight.weights->amount.second/65535);
				auto _weights = std::make_shared<shares::weight::weight_element>(script, new_weight);

				// - total_donation_weight1 + (desired_weight - total_weight1)//65535*total_donation_weight2//(total_weight2//65535)
				auto total_donation = cur.weight.total_donation_weight + (desired_weight - cur.weight.total_weight)/65535*x.weight.total_donation_weight/(x.weight.total_weight/65535);
				shares::weight::weight_element_type new_weights(_weights, desired_weight, total_donation);

				x.weight = new_weights;
				i = x;
			} else
			{
				// (it; best]
				i = get_sum(best.head, it->first);
			}
		}
		else
		{
			i = best;
		}

		assert((i.height <= max_shares) && (i.weight.total_weight <= desired_weight));
		assert((i.height == max_shares) || (i.weight.total_weight == desired_weight));

		auto weights = i.weight.weights->get_map();
		auto total_weight = i.weight.total_weight;
		auto donation_weight = i.weight.total_donation_weight;

		return std::make_tuple(weights, total_weight, donation_weight);
	}

    // from p2pool::share
    std::vector<uint256> get_other_tx_hashes(ShareType share);

    std::vector<coind::data::tx_type> _get_other_txs(ShareType share, const std::map<uint256, coind::data::tx_type> &known_txs);

    std::tuple<bool, std::string> should_punish_reason(ShareType share, uint256 previous_block, uint32_t bits, const std::map<uint256, coind::data::tx_type> &known_txs);
};
