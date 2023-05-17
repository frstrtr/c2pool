#pragma once

#include <memory>

#include "base_share_tracker.h"
#include "share_store.h"

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
    std::vector<std::tuple<std::tuple<arith_uint256, int32_t, int32_t>, arith_uint256>> decorated_heads;
    std::set<std::tuple<std::string, std::string>> bad_peer_addresses;
};

class ShareTracker : public BaseShareTracker, public std::enable_shared_from_this<ShareTracker>
{
public:
    ShareStore share_store;
    VerifiedShareTracker verified;
public:
    shared_ptr<c2pool::Network> net;
    shared_ptr<coind::ParentNetwork> parent_net;
public:
    ShareTracker(shared_ptr<c2pool::Network> _net);

    void init(const std::vector<ShareType>& _shares, const std::vector<uint256>& known_verified_share_hashes);

    ShareType get(uint256 hash);

    void add(ShareType share) override;
    void remove(uint256 hash);

    bool attempt_verify(ShareType share);

    TrackerThinkResult think(const std::function<int32_t(uint256)>& block_rel_height_func, uint256 previous_block, uint32_t bits, std::map<uint256, coind::data::tx_type> known_txs);

    arith_uint288 get_pool_attempts_per_second(uint256 previous_share_hash, int32_t dist, bool min_work = false);

    // returns approximate lower bound on chain's hashrate in the last CHAIN_LENGTH*15//16*SHARE_PERIOD time
    std::tuple<int32_t, arith_uint288> score(uint256 share_hash, const std::function<int32_t(uint256)> &block_rel_height_func)
    {
        arith_uint288 score_res;
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

        score_res = verified.get_sum(share_hash, end_point).work /
                    ((-block_height.value() + 1) * parent_net->BLOCK_PERIOD);

        return std::make_tuple(net->CHAIN_LENGTH, score_res);
    }

    std::map<uint64_t, uint256> get_desired_version_counts(uint256 best_share_hash, uint64_t dist)
    {
        std::map<uint64_t, arith_uint288> _result;

        auto get_chain_func = get_chain(best_share_hash, dist);
        uint256 hash;

        while(get_chain_func(hash))
        {
            auto share = get(hash);

            if (_result.find(*share->desired_version) == _result.end())
                _result[*share->desired_version] = 0;

            _result[*share->desired_version] += coind::data::target_to_average_attempts(share->target) + 1;
        }

        std::map<uint64_t, uint256> result;
        for (auto v : _result)
        {
            result[v.first] = ArithToUint256(v.second);
        }
        return result;
    }

    std::tuple<std::map<std::vector<unsigned char>, arith_uint288>, arith_uint288, arith_uint288>
    get_cumulative_weights(uint256 start, int32_t max_shares, arith_uint288 desired_weight)
    {
        // Если start -- None/Null/0 шара.
        if (start.IsNull())
            return {{},{}, {}};

        auto [start_height, last] = get_height_and_last(start);

        // Ограничиваем цепочку до размера max_shares.
        if (start_height > max_shares)
        {
            last = get_nth_parent_key(start, max_shares);
        }

        // Поиск desired_weight
        std::map<std::vector<unsigned char>, arith_uint288> weights;

        auto desired_sum_weight = get_sum_to_last(start).weight.total_weight >= desired_weight ? get_sum_to_last(start).weight.total_weight - desired_weight : arith_uint288();
        auto cur = get_sum_to_last(start);
        auto prev = get_sum_to_last(start);
        std::optional<shares::weight::weight_data> extra_ending;

        while(cur.hash() != last)
        {
            if (cur.weight.total_weight >= desired_sum_weight)
            {
                for (auto [k, v]: cur.weight.amount)
                {
                    if (weights.find(k) != weights.end())
                    {
                        weights[k] += v;
                    } else
                    {
                        weights[k] = v;
                    }
                }
            } else
            {
//                auto [_script, _weight] = *cur.weight.amount.begin();
                extra_ending = std::make_optional<shares::weight::weight_data>(cur.share); //TODO: check
                break;
            }

            prev = cur;

            if (items.count(cur.prev()))
//            if (cur.prev != sum.end())
            {
//                cur = cur.prev->second;
                cur = items[cur.prev()];
            } else
            {
                break;
            }
        }

        if (extra_ending.has_value())
        {
            auto result_sum = get_sum(start, prev.hash());
            //total weights
            auto total_weights = result_sum.weight.total_weight;
            //total donation weights
            auto total_donation_weights = result_sum.weight.total_donation_weight;

            auto [_script, _weight] = *extra_ending->amount.begin();
            //TODO: test
            std::pair<std::vector<unsigned char>, arith_uint288> new_weight = {_script,
                                                                               (desired_weight - total_weights) /
                                                                               65535 * _weight /
                                                                               (extra_ending->total_weight / 65535)
            };

            if (weights.find(new_weight.first) != weights.end())
            {
                weights[new_weight.first] += new_weight.second;
            } else
            {
                weights[new_weight.first] = new_weight.second;
            }

            total_donation_weights += (desired_weight - total_weights)/65535*extra_ending->total_donation_weight/(extra_ending->total_weight/65535);
            total_weights = desired_weight;

            return std::make_tuple(weights, total_weights, total_donation_weights);
        } else
        {
            auto result_sum = get_sum(start, cur.prev());
            //total weights
            auto total_weights = result_sum.weight.total_weight;
            //total donation weights
            auto total_donation_weights = result_sum.weight.total_donation_weight;

            return std::make_tuple(weights, total_weights, total_donation_weights);
        }
    }

    // from p2pool::share
    std::vector<uint256> get_other_tx_hashes(ShareType share);

    std::vector<coind::data::tx_type> _get_other_txs(ShareType share, const std::map<uint256, coind::data::tx_type> &known_txs);

    std::tuple<bool, std::string> should_punish_reason(ShareType share, uint256 previous_block, uint32_t bits, const std::map<uint256, coind::data::tx_type> &known_txs);
};

