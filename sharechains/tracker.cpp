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
#include <cmath>
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
    GeneratedShare ShareTracker::generate_share_transactions(ShareData share_data, uint256 block_target, int32_t desired_timestamp, uint256 desired_target, MerkleLink ref_merkle_link, vector<tuple<uint256, int32_t>> desired_other_transaction_hashes_and_fees, map<uint256, UniValue> known_txs = map<uint256, UniValue>(), unsigned long long last_txout_nonce = 0, long long base_subsidy = 0, UniValue other_data = UniValue())
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
        auto height = std::get<0>(get_height_and_last);
        auto height = std::get<1>(get_height_and_last);
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
        int32_t all_transaction_stripped_size = 0;
        int32_t new_transaction_weight = 0;
        int32_t all_transaction_weight = 0;
        vector<tuple<int, int>> transaction_hash_refs;
        vector<uint256> other_transaction_hashes;

        //t1

        auto past_shares = get_chain(share_data['previous_share_hash'], std::min(height, 100));
        map<uint256, tuple<int, int>> tx_hash_to_this;

        for (int i = 0; i < past_shares.size(); i++)
        {
            auto _share = past_shares[i];
            for (int j = 0; j < _share.new_transaction_hashes.size(); j++)
            {
                auto tx_hash = _share.new_transaction_hashes[j];
                if (tx_hash_to_this.find(tx_hash) == tx_hash_to_this.end())
                {
                    tx_hash_to_this[tx_hash] = std::make_tuple(1 + i, j);
                }
            }
        }

        //t2

        for (auto item : desired_other_transaction_hashes_and_fees)
        {
            auto tx_hash = std::get<0>(item);
            auto fee = std::get<1>(item);

            int32_t this_stripped_size = 0;
            int32_t this_real_size = 0;
            int32_t this_weight = 0;
            if (!known_txs.empty())
            {
                this_stripped_size = c2pool::python::PyPackTypes::packed_size("tx_id_type", known_txs[tx_hash]);
                this_real_size = c2pool::python::PyPackTypes::packed_size("tx_type", known_txs[tx_hash]);
                this_weight = this_real_size + 3 * this_stripped_size;
            }

            if (all_transaction_stripped_size + this_stripped_size + 80 + BaseShare::gentx_size + 500 > net()->BLOCK_MAX_SIZE)
                break;
            if (all_transaction_weight + this_weight + 4 * 80 + BaseShare::gentx_size + 2000 > net()->BLOCK_MAX_WEIGHT)
                break;

            tuple<int, int> _this;
            all_transaction_stripped_size += this_stripped_size;
            all_transaction_real_size += this_real_size;
            all_transaction_weight += this_weight;
            if (tx_hash_to_this.find(tx_hash) != tx_hash_to_this.end())
            {
                _this = tx_hash_to_this[tx_hash];
            }
            else
            {
                new_transaction_size += this_real_size;
                new_transaction_weight += this_weight;

                new_transaction_hashes.push_back(tx_hash);
                _this = std::make_tuple(0, new_transaction_hashes.size()-1);
            }
            transaction_hash_refs.push_back(_this);
            other_transaction_hashes.push_back(tx_hash);
        }

        //t3

        // Тут в питон-коде проводятся махинации с упаковкой в типы C, для оптимизации памяти. Нам, по идее, это не нужно.
        // if transaction_hash_refs and max(transaction_hash_refs) < 2**16:
        //     transaction_hash_refs = array.array('H', transaction_hash_refs)
        // elif transaction_hash_refs and max(transaction_hash_refs) < 2**32: # in case we see blocks with more than 65536 tx
        //     transaction_hash_refs = array.array('L', transaction_hash_refs)

        //t4


        // if all_transaction_stripped_size:
        //     print "Generating a share with %i bytes, %i WU (new: %i B, %i WU) in %i tx (%i new), plus est gentx of %i bytes/%i WU" % (
        //         all_transaction_real_size,
        //         all_transaction_weight,
        //         new_transaction_size,
        //         new_transaction_weight,
        //         len(other_transaction_hashes),
        //         len(new_transaction_hashes),
        //         cls.gentx_size,
        //         cls.gentx_weight)
        //     print "Total block stripped size=%i B, full size=%i B,  weight: %i WU" % (
        //         80+all_transaction_stripped_size+cls.gentx_size, 
        //         80+all_transaction_real_size+cls.gentx_size, 
        //         3*80+all_transaction_weight+cls.gentx_weight)

        
        set<uint256> included_transactions = set<uint256>(other_transaction_hashes.begin(), other_transaction_hashes.end());
        
        vector<int32_t> removed_fee;
        int32_t definite_fees;
        for (auto item : desired_other_transaction_hashes_and_fees)
        {
            auto tx_hash = std::get<0>(item);
            auto fee = std::get<1>(item);

            if (included_transactions.find(tx_hash) == included_transactions.end())
                {removed_fee.push_back(fee);}
            else {
                //TODO if fee is None -> +0
                definite_fees += fee;
            }
        }

        

        return {share_info, gentx, other_transaction_hashes, get_share};
    }
}