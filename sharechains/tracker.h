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
#include "prefsum_share.h"
#include <btclibs/uint256.h>
#include <btclibs/arith_uint256.h>
#include <libcoind/data.h>
#include <libcoind/transaction.h>
#include <libdevcore/logger.h>
#include <libdevcore/common.h>
#include <networks/network.h>
using namespace c2pool::shares;

class Share;
class GeneratedShare;

#define LOOKBEHIND 200
//TODO: multi_index for more speed https://www.boost.org/doc/libs/1_76_0/libs/multi_index/doc/index.html

struct TrackerThinkResult
{
	uint256 best_hash;
	std::vector<std::tuple<std::tuple<std::string, std::string>, uint256>> desired;
	std::vector<uint256> decorated_heads; //TODO: TYPE???
	std::set<std::tuple<std::string, std::string>> bad_peer_addresses;
};

class ShareTracker : public PrefsumShare, public enable_shared_from_this<ShareTracker>
{
public:
	PrefsumVerifiedShare verified;
public:
	shared_ptr<c2pool::Network> net;
	shared_ptr<coind::ParentNetwork> parent_net;
public:
	ShareTracker(shared_ptr<c2pool::Network> _net);

	ShareType get(uint256 hash);

	void add(ShareType share);

	bool attempt_verify(ShareType share);

	TrackerThinkResult think(boost::function<int32_t(uint256)> block_rel_height_func);

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

		auto end_point = verified.get_nth_parent_hash(share_hash, net->CHAIN_LENGTH * 15 / 16);

		boost::optional<int32_t> block_height;
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

		score_res = ArithToUint256(verified.get_delta(share_hash, end_point).work /
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
};
