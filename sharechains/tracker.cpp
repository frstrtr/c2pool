#include "tracker.h"
#include "share.h"
using namespace c2pool::shares::share;

#include <univalue.h>
#include <btclibs/uint256.h>
#include <devcore/logger.h>
#include <devcore/common.h>

#include <map>
#include <queue>
#include <memory>
using std::map;
using std::queue;
using std::shared_ptr;

#include <boost/format.hpp>

namespace c2pool::shares::tracker
{
    void LookbehindDelta::push(shared_ptr<BaseShare> share)
    {
        if (_queue.size() == LOOKBEHIND)
        {
            shared_ptr<BaseShare> temp = _queue.front();

            work = work - coind::data::target_to_average_attempts(temp->target);
            min_work = min_work - coind::data::target_to_average_attempts(temp->max_target);
            _queue.pop();
        }

        _queue.push(share);
        work = work + coind::data::target_to_average_attempts(share->target);
        min_work = min_work + coind::data::target_to_average_attempts(share->max_target);
    }
}

namespace c2pool::shares::tracker
{
    ShareTracker::ShareTracker(shared_ptr<c2pool::libnet::NodeManager> mng) : c2pool::libnet::INodeMember(mng) {}

    shared_ptr<BaseShare> ShareTracker::get(uint256 hash)
    {
        try
        {
            auto share = items.at(hash);
            return share;
        }
        catch (const std::out_of_range &e)
        {
            return nullptr;
        }
    }

    void ShareTracker::add(shared_ptr<BaseShare> share)
    {
        if (!share)
        {
            LOG_WARNING << "ShareTracker::add called, when share = nullptr!";
            return;
        }

        if (items.find(share->hash) != items.end())
        {
            items[share->hash] = share;
        }
        else
        {
            LOG_WARNING << share->hash.ToString() << " item already present"; //TODO: for what???
        }

        lookbehind_items.push(share);
    }

    bool ShareTracker::attempt_verify(BaseShare share)
    {
        if (verified.find(share.hash) != verified.end())
        {
            return true;
        }

        try
        {
            share.check(shared_from_this());
        }
        catch (const std::invalid_argument &e)
        {
            LOG_WARNING << e.what() << '\n';
            return false;
        }
    }

    TrackerThinkResult ShareTracker::think()
    {
    }

    //TODO: template method, where T1 = type(share)???
    GeneratedShare ShareTracker::generate_share_transactions(ShareData share_data, uint256 block_target, int32_t desired_timestamp, uint256 desired_target, MerkleLink ref_merkle_link, vector<tuple<uint256, int32_t>> desired_other_transaction_hashes_and_fees, map<uint256, UniValue> known_txs = map<uint256, UniValue>(), unsigned long long last_txout_nonce = 0, long long base_subsidy = 0, UniValue other_data)
    {
        //t0
        shared_ptr<BaseShare> previous_share;
        if (share_data.previous_share_hash)
        {
            previous_share = nullptr;
        }
        else
        {
            previous_share = items[share_data.previous_share_hash]
        }

        //height, last
        auto get_height_and_last = get_height_and_last(share_data.previous_share_hash);
        assert(height >= net->REAL_CHAIN_LENGTH) || (last == nullptr);

        arith_uint256 pre_target3;
        if (height < net->TARGET_LOOKBEHIND)
        {
            pre_target3 = net->MAX_TARGET;
        }
        else
        {
            auto attempts_per_second = get_pool_attempts_per_second(share_data.previous_share_hash, net->TARGET_LOOKBEHIND, true, true);
            //TODO: 
            // pre_target = 2**256//(net.SHARE_PERIOD*attempts_per_second) - 1 if attempts_per_second else 2**256-1
            // pre_target2 = math.clip(pre_target, (previous_share.max_target*9//10, previous_share.max_target*11//10))
            // pre_target3 = math.clip(pre_target2, (net.MIN_TARGET, net.MAX_TARGET))
        }
        //TODO:
        // max_bits = bitcoin_data.FloatingInteger.from_target_upper_bound(pre_target3)
        // bits = bitcoin_data.FloatingInteger.from_target_upper_bound(math.clip(desired_target, (pre_target3//30, pre_target3)))

        vector<uint256> new_transaction_hashes;
        unsigned long long all_transaction_stripped_size = 0;
        vector<tuple<int, int>> transaction_hash_refs;
        vector<uint256> other_transaction_hashes;

        //t1

        auto past_shares = get_chain(share_data['previous_share_hash'])





        return {share_info, gentx, other_transaction_hashes, get_share};
    }
}