#pragma once

#include <univalue.h>
#include "shareTypes.h"
#include <btclibs/uint256.h>
#include <btclibs/arith_uint256.h>
#include <coind/data.h>
#include <devcore/logger.h>
#include <devcore/common.h>
#include <libnet/node_manager.h>
#include "prefsum_share.h"
#include <devcore/pystruct.h>
#include <libnet/node_manager.h>

#include <map>
#include <vector>
#include <string>
#include <memory>
#include <set>
#include <tuple>

using namespace std;

#include <boost/function.hpp>

namespace c2pool::shares
{
    class BaseShare;
} // namespace c2pool::shares

using namespace c2pool::shares;

#define LOOKBEHIND 200
//TODO: multi_index for more speed https://www.boost.org/doc/libs/1_76_0/libs/multi_index/doc/index.html
namespace c2pool::shares
{
    typedef boost::function<shared_ptr<BaseShare>(/*TODO: args*/)> get_share_method;

    struct GeneratedShare
    {
        ShareInfo share_info; //TODO: sharechain[v1]::ShareTypes.h::ShareInfoType
        UniValue gentx;       //TODO: just tx
        vector<uint256> other_transaction_hashes;
        get_share_method get_share;
    };

    struct TrackerThinkResult
    {
        uint256 best_hash;
        std::vector<std::tuple<std::tuple<std::string, std::string>, uint256>> desired;
        std::vector<uint256> decorated_heads; //TODO: TYPE???
        std::set<std::tuple<std::string, std::string>> bad_peer_addresses;
    };

    class ShareTracker : public c2pool::libnet::NodeMember, public enable_shared_from_this<ShareTracker>
    {
    private:
        PrefsumShare shares;
        PrefsumVerifiedShare verified;

    public:
        ShareTracker(shared_ptr<c2pool::libnet::NodeManager> mng);

        shared_ptr<BaseShare> get(uint256 hash);
        void add(shared_ptr<BaseShare> share);

        bool attempt_verify(shared_ptr<BaseShare> share);

        TrackerThinkResult think();

       
        int32_t get_height_rel_highest(uint256 prev_block_hash){
             //TODO:
        }

        uint256 get_pool_attempts_per_second(uint256 previous_share_hash, int32_t dist, bool min_work = false);

        ///in p2pool - generate_transaction | segwit_data in other_data
        template <typename ShareType>
        GeneratedShare generate_share_transactions(ShareData share_data, uint256 block_target, int32_t desired_timestamp, uint256 desired_target, MerkleLink ref_merkle_link, vector<tuple<uint256, boost::optional<int32_t>>> desired_other_transaction_hashes_and_fees, map<uint256, UniValue> known_txs = map<uint256, UniValue>(), unsigned long long last_txout_nonce = 0, long long base_subsidy = 0, UniValue other_data = UniValue())
        {
            //t0
            shared_ptr<BaseShare> previous_share;
            if (share_data.previous_share_hash)
            {
                previous_share = nullptr;
            }
            else
            {
                previous_share = shares.items[share_data.previous_share_hash];
            }

            //height, last
            auto get_height_and_last = shares.get_height_and_last(share_data.previous_share_hash);
            auto height = std::get<0>(get_height_and_last);
            auto last = std::get<1>(get_height_and_last);
            assert(height >= net()->REAL_CHAIN_LENGTH) || (last.IsNull());

            arith_uint256 pre_target3;
            if (height < net()->TARGET_LOOKBEHIND)
            {
                pre_target3 = net()->MAX_TARGET;
            }
            else
            {
                auto attempts_per_second = get_pool_attempts_per_second(share_data.previous_share_hash, net()->TARGET_LOOKBEHIND, true);
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

            auto past_shares_generator = shares.get_chain(previous_share->hash, std::min(height, 100));
            map<uint256, tuple<int, int>> tx_hash_to_this;

            {
                uint256 _hash;
                int32_t i = 0;
                while (past_shares_generator(_hash))
                {
                    auto _share = shares.items[_hash];
                    for (int j = 0; j < _share->new_transaction_hashes.size(); j++)
                    {
                        auto tx_hash = _share->new_transaction_hashes[j];
                        if (tx_hash_to_this.find(tx_hash) == tx_hash_to_this.end())
                        {
                            tx_hash_to_this[tx_hash] = std::make_tuple(1 + i, j);
                        }
                    }
                    i += 1;
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
                //all_transaction_real_size += this_real_size;
                all_transaction_weight += this_weight;
                if (tx_hash_to_this.find(tx_hash) != tx_hash_to_this.end())
                {
                    _this = tx_hash_to_this[tx_hash];
                }
                else
                {
                    //new_transaction_size += this_real_size;
                    new_transaction_weight += this_weight;

                    new_transaction_hashes.push_back(tx_hash);
                    _this = std::make_tuple(0, new_transaction_hashes.size() - 1);
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

            vector<boost::optional<int32_t>> removed_fee;
            int32_t removed_fee_sum;
            int32_t definite_fees;
            bool fees_none_contains = false;
            for (auto item : desired_other_transaction_hashes_and_fees)
            {
                auto tx_hash = std::get<0>(item);
                auto fee = std::get<1>(item);
                if (!fee.has_value())
                    fees_none_contains = true;

                if (included_transactions.find(tx_hash) == included_transactions.end())
                {
                    removed_fee.push_back(fee);
                    if (fee.has_value())
                        removed_fee_sum += fee.get();
                }
                else
                {
                    if (fee.has_value())
                        definite_fees += fee.get();
                    else
                        definite_fees += 0;
                }
            }

            if (!fees_none_contains)
            {
                share_data.subsidy += removed_fee_sum;
            }
            else
            {
                share_data.subsidy = base_subsidy + definite_fees;
            }

            /*TODO:
            weights, total_weight, donation_weight = tracker.get_cumulative_weights(previous_share.share_data['previous_share_hash'] if previous_share is not None else None,
            max(0, min(height, net.REAL_CHAIN_LENGTH) - 1),
            65535*net.SPREAD*bitcoin_data.target_to_average_attempts(block_target),
        )
        */
            //TODO: types
            tuple<int32_t, int32_t, int32_t> cumulative_weights; //TODO: Реализовать get_cumulative_weights
            int32_t weights = std::get<0>(cumulative_weights);
            int32_t total_weight = std::get<1>(cumulative_weights);
            int32_t donation_weight = std::get<2>(cumulative_weights);
            //TODO: [assert] assert total_weight == sum(weights.itervalues()) + donation_weight, (total_weight, sum(weights.itervalues()) + donation_weight)

            /*TODO:
            amounts = dict((script, share_data['subsidy']*(199*weight)//(200*total_weight)) for script, weight in weights.iteritems()) # 99.5% goes according to weights prior to this share
            this_script = bitcoin_data.pubkey_hash_to_script2(share_data['pubkey_hash'])
            amounts[this_script] = amounts.get(this_script, 0) + share_data['subsidy']//200 # 0.5% goes to block finder
            amounts[DONATION_SCRIPT] = amounts.get(DONATION_SCRIPT, 0) + share_data['subsidy'] - sum(amounts.itervalues()) # all that's left over is the donation weight and some extra satoshis due to rounding
            
            if sum(amounts.itervalues()) != share_data['subsidy'] or any(x < 0 for x in amounts.itervalues()):
                raise ValueError()

            dests = sorted(amounts.iterkeys(), key=lambda script: (script == DONATION_SCRIPT, amounts[script], script))[-4000:] # block length limit, unlikely to ever be hit
        */

            bool segwit_activated = ShareType::is_segwit_activated();
            if (!other_data.exists("segwit_data") && known_txs.empty())
            {
                segwit_activated = false;
            }

            bool segwit_tx = false;
            for (auto _tx_hash : other_transaction_hashes)
            {
                if (coind::data::is_segwit_tx(known_txs[_tx_hash]))
                    segwit_tx = true;
            }
            if (!(segwit_activated || known_txs.empty()) && segwit_tx)
            {
                throw "segwit transaction included before activation";
            }
            /*TODO:
            if segwit_activated and known_txs is not None:
                share_txs = [(known_txs[h], bitcoin_data.get_txid(known_txs[h]), h) for h in other_transaction_hashes]
                segwit_data = dict(txid_merkle_link=bitcoin_data.calculate_merkle_link([None] + [tx[1] for tx in share_txs], 0), wtxid_merkle_root=bitcoin_data.merkle_hash([0] + [bitcoin_data.get_wtxid(tx[0], tx[1], tx[2]) for tx in share_txs]))
            if segwit_activated and segwit_data is not None:
                witness_reserved_value_str = '[P2Pool]'*4
                witness_reserved_value = pack.IntType(256).unpack(witness_reserved_value_str)
                witness_commitment_hash = bitcoin_data.get_witness_commitment_hash(segwit_data['wtxid_merkle_root'], witness_reserved_value)
        */

            uint256 far_share_hash;
            if (last.IsNull() && height < 99)
            {
                far_share_hash.SetNull();
            }
            else
            {
                far_share_hash = shares.get_nth_parent_hash(share_data.previous_share_hash, 99);
            }

            int32_t result_timestamp;

            if (previous_share != nullptr)
            {
                if (ShareType::VERSION < 32)
                {
                    result_timestamp = std::clamp(desired_timestamp, previous_share->timestamp + 1, previous_share->timestamp + net()->SHARE_PERIOD * 2 - 1);
                }
                else
                {
                    result_timestamp = std::max(desired_timestamp, previous_share->timestamp + 1);
                }
            }
            else
            {
                result_timestamp = desired_timestamp;
            }

            unsigned long absheight = 1;
            if (previous_share != nullptr)
            {
                absheight += previous_share->absheight;
            }
            absheight %= 4294967296; //% 2**32

            uint128 abswork;
            if (previous_share != nullptr)
            {
                abswork = previous_share->abswork;
            }
            //TODO: abswork=((previous_share.abswork if previous_share is not None else 0) + bitcoin_data.target_to_average_attempts(bits.target)) % 2**128,

            ShareInfo share_info = {share_data,
                                    far_share_hash,
                                    0, //TODO:max_bits,
                                    0, //TODO:bits,
                                    result_timestamp,
                                    new_transaction_hashes,
                                    transaction_hash_refs,
                                    absheight,
                                    abswork};

            if (previous_share != nullptr)
            {
                if (desired_timestamp > (previous_share->timestamp + 180))
                {
                    LOG_WARNING << (boost::format("Warning: Previous share's timestamp is %1% seconds old.\n \
                            Make sure your system clock is accurate, and ensure that you're connected to decent peers.\n \
                            If your clock is more than 300 seconds behind, it can result in orphaned shares.\n \
                            (It's also possible that this share is just taking a long time to mine.)") %
                                    (desired_timestamp - previous_share->timestamp))
                                       .str();
                }

                if (previous_share->timestamp > (c2pool::dev::timestamp() + 3))
                {
                    LOG_WARNING << (boost::format("WARNING! Previous share's timestamp is %1% seconds in the future. This is not normal.\n \
                                              Make sure your system clock is accurate.Errors beyond 300 sec result in orphaned shares.") %
                                    (previous_share->timestamp - c2pool::dev::timestamp()))
                                       .str();
                }
            }
            UniValue gentx; //TODO: remove
            /*TODO: SEGWIT
        
        if (segwit_activated){
            share_info.segwit_data = segwit_data;
        }

        gentx = dict(
            version=1,
            tx_ins=[dict(
                previous_output=None,
                sequence=None,
                script=share_data['coinbase'],
            )],
            tx_outs=([dict(value=0, script='\x6a\x24\xaa\x21\xa9\xed' + pack.IntType(256).pack(witness_commitment_hash))] if segwit_activated else []) +
                [dict(value=amounts[script], script=script) for script in dests if amounts[script] or script == DONATION_SCRIPT] +
                [dict(value=0, script='\x6a\x28' + cls.get_ref_hash(net, share_info, ref_merkle_link) + pack.IntType(64).pack(last_txout_nonce))],
            lock_time=0,
        )
        if segwit_activated:
            gentx['marker'] = 0
            gentx['flag'] = 1
            gentx['witness'] = [[witness_reserved_value_str]] */

            get_share_method get_share([=](SmallBlockHeaderType header, unsigned long long last_txout_nonce)
                                       {
                                           auto min_header = header;
                                           shared_ptr<BaseShare> share = std::make_shared<ShareType>(); //TODO: GENERATE SHARE IN CONSTUCTOR
                                       });

            /*
            t5 = time.time()
            if p2pool.BENCH: print "%8.3f ms for data.py:generate_transaction(). Parts: %8.3f %8.3f %8.3f %8.3f %8.3f " % (
                (t5-t0)*1000.,
                (t1-t0)*1000.,
                (t2-t1)*1000.,
                (t3-t2)*1000.,
                (t4-t3)*1000.,
                (t5-t4)*1000.)
        */

            return {share_info, gentx, other_transaction_hashes, get_share};
        }

        std::tuple<int32_t, uint256> score(uint256 share_hash)
        {
            uint256 score_res;
            score_res.SetNull();
            auto head_height = verified.get_height(share_hash);
            if (head_height < net()->CHAIN_LENGTH)
            {
                return std::make_tuple(head_height, score_res);
            }

            auto end_point = verified.get_nth_parent_hash(share_hash, net()->CHAIN_LENGTH * 15 / 16);

            boost::optional<int32_t> block_height;
            auto gen_verif_chain = verified.get_chain(end_point, net()->CHAIN_LENGTH / 16);

            uint256 hash;
            while (gen_verif_chain(hash))
            {
                auto share = verified.items[hash];

                auto block_height_temp = get_height_rel_highest(share->header.previous_block);
                if (!block_height.has_value())
                {
                    block_height = block_height_temp;
                }
                else
                {
                    if (block_height.value() > block_height_temp)
                    {
                        block_height = block_height_temp;
                    }
                }
            }

            score_res = ArithToUint256(verified.get_delta(share_hash, end_point).work / ((-block_height.value() + 1)*netParent()->BLOCK_PERIOD));
            return std::make_tuple(net()->CHAIN_LENGTH, score_res);
        }
    };
} // namespace c2pool::shares
