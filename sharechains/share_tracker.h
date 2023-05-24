#pragma once

#include <memory>

#include "base_share_tracker.h"
#include "share_store.h"

class PrepareListNode
{
public:
    ShareType value;

    std::shared_ptr<PrepareListNode> prev;
    std::shared_ptr<PrepareListNode> next;

    PrepareListNode() {};
    PrepareListNode(ShareType& _value)
    {
        value = _value;
    }
};

typedef std::shared_ptr<PrepareListNode> ptr_node;

class PrepareFork
{
public:
    ptr_node head;
    ptr_node tail;

    PrepareFork(ptr_node _node)
    {
        head = _node;
        tail = _node;
    }
};

class PreparedList
{
private:
    typedef std::shared_ptr<PrepareFork> ptr_fork;
private:
    std::map<uint256, ptr_node> nodes;

    ptr_node make_node(ShareType &value)
    {
        auto v = std::make_shared<PrepareListNode>(value);
        nodes[value->hash] = v;

        return v;
    }

    // Метод создаёт пару из двух нод
    void make_pair(ptr_node left, ptr_node right)
    {
        left->next = right;
        right->prev = left;
    }

    ptr_fork merge_fork(ptr_fork left, ptr_fork right)
    {
        make_pair(left->head, right->tail);
        left->head = right->head;
        return left;
    }
public:
    std::vector<ptr_fork> forks;

    PreparedList(std::vector<ShareType> data)
    {
        // Prepare data
        // -- map hashes
        std::map<uint256, ShareType> hashes;
        for (auto &_share : data)
        {
            hashes[_share->hash] = _share;
        }

        // -- heads/tails

        std::map<uint256, ptr_fork> heads;
        std::map<uint256, ptr_fork> tails;

        while (!hashes.empty())
        {
            auto node = make_node(hashes.begin()->second);
            hashes.erase(node->value->hash);

            if (!heads.count(*node->value->previous_hash) && !tails.count(node->value->hash))
            {
                std::map<uint256, ShareType>::iterator it;
                // make new fork
                {
                    auto new_fork = std::make_shared<PrepareFork>(node);
                    heads[node->value->hash] = new_fork;
                    tails[*node->value->previous_hash] = new_fork;
                }

                while ((it = hashes.find(*node->value->previous_hash)) != hashes.end())
                {
                    auto new_node = make_node(it->second);
                    hashes.erase(it->first);
                    make_pair(new_node, node);

                    auto _fork = tails.extract(*node->value->previous_hash);
                    _fork.mapped()->tail = new_node;
                    _fork.key() = *new_node->value->previous_hash;
                    tails.insert(std::move(_fork));

                    node = new_node;
                }
                continue;
            }

            // Проверка на продолжение форка спереди
            if (heads.find(*node->value->previous_hash) != heads.end())
            {
                auto _fork = heads.extract(*node->value->previous_hash);
                make_pair(_fork.mapped()->head, node);

                _fork.mapped()->head = node;
                _fork.key() = node->value->hash;
                heads.insert(std::move(_fork));

                hashes.erase(node->value->hash);
            }

            // Проверка на merge форков.
            if (tails.find(node->value->hash) != tails.end())
            {
                auto left_fork = heads.extract(node->value->hash);
                auto right_fork = tails.extract(node->value->hash);

                auto new_fork = merge_fork(left_fork.mapped(), right_fork.mapped());
                heads[new_fork->head->value->hash] = new_fork;
                tails[*new_fork->tail->value->previous_hash] = new_fork;
            }
        }

        // set forks
        for (auto &_forks : heads)
        {
            forks.push_back(_forks.second);
        }
    }
};

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
        LOG_TRACE << "start_height = " << start_height << ", last = " << last;
        LOG_TRACE << "max_shares = " << max_shares;

        // Ограничиваем цепочку до размера max_shares.
        if (start_height > max_shares)
        {
            last = get_nth_parent_key(start, max_shares);
        }
        LOG_TRACE << "last = " << last;

        // Поиск desired_weight
        std::map<std::vector<unsigned char>, arith_uint288> weights;

        auto desired_sum_weight = std::get<0>(get_sum_to_last(start)).weight.total_weight >= desired_weight ? std::get<0>(get_sum_to_last(start)).weight.total_weight - desired_weight : arith_uint288();
        LOG_TRACE << "start = " << start;
        auto cur = get_sum_to_last(start);
        auto prev = get_sum_to_last(start);
        LOG_TRACE << "desired_sum_weight = " << desired_weight.GetHex() << ", cur = " << std::get<0>(cur).hash() << ", prev = " << std::get<0>(prev).hash();
        std::optional<shares::weight::weight_data> extra_ending;

        while(std::get<0>(cur).hash() != last)
        {
            if (std::get<0>(cur).weight.total_weight >= desired_sum_weight)
            {
                std::fstream f;
                f.open("/home/sl33n/c2pool/cmake-build-debug/weights2.txt", ios_base::in | ios_base::out | ios_base::app);
                f << "[";
                for (auto [k, v]: std::get<0>(cur).weight.amount)
                {
                    if (weights.find(k) != weights.end())
                    {
                        weights[k] += v;
                    } else
                    {
                        weights[k] = v;
                    }
                    f << " (" << k << " : " << v.GetHex() << "); ";
                }
                f << "]\n";
                std::fstream f2;
                f2.open("/home/sl33n/c2pool/cmake-build-debug/weights3_c2pool.txt", ios_base::in | ios_base::out | ios_base::app);
                f2 << (coind::data::target_to_average_attempts(std::get<0>(cur).share->target) * 65535).GetHex() << "\n";//std::get<0>(cur).weight.total_weight.GetHex() << "\n";//std::accumulate(result_sum.weight.amount.begin(), result_sum.weight.amount.end(), arith_uint288{}, [](auto x, const auto &p) {return x + p.second;}).GetHex() << "\n";
            } else
            {
//                auto [_script, _weight] = *cur.weight.amount.begin();
                extra_ending = std::make_optional<shares::weight::weight_data>(std::get<0>(cur).share); //TODO: check
                break;
            }

            prev = cur;

            if (items.count(std::get<0>(cur).prev()))
//            if (cur.prev != sum.end())
            {
//                cur = cur.prev->second;
//                cur = items[cur.prev()];
                cur = get_sum_to_last(std::get<0>(cur).prev());
            } else
            {
                break;
            }
//            LOG_TRACE << "cur = " << std::get<0>(cur).hash();
        }

        if (extra_ending.has_value())
        {
            auto result_sum = get_sum(start, std::get<0>(prev).hash());
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
            std::cout << "get_sum: " << start << " " << std::get<1>(cur) << " " << std::get<2>(cur) << std::endl;
            auto result_sum = get_sum(start, /*std::get<2>(prev)*/std::get<0>(prev).prev());
            //total weights
            auto total_weights = result_sum.weight.total_weight;
            //total donation weights
            auto total_donation_weights = result_sum.weight.total_donation_weight;

            LOG_TRACE << "height: " << result_sum.height;
            LOG_TRACE << "result_sum: " << std::accumulate(result_sum.weight.amount.begin(), result_sum.weight.amount.end(), arith_uint288{}, [](auto x, const auto &p) {return x + p.second;}).GetHex();
            LOG_TRACE << "weights: " << std::accumulate(weights.begin(), weights.end(), arith_uint288{}, [](auto x, const auto &p) {return x + p.second;}).GetHex();
            LOG_TRACE << "total_weights: " << total_weights.GetHex();
            LOG_TRACE << "total_donation_weights: " << total_donation_weights.GetHex();

            return std::make_tuple(result_sum.weight.amount, total_weights, total_donation_weights);
        }
    }

    // from p2pool::share
    std::vector<uint256> get_other_tx_hashes(ShareType share);

    std::vector<coind::data::tx_type> _get_other_txs(ShareType share, const std::map<uint256, coind::data::tx_type> &known_txs);

    std::tuple<bool, std::string> should_punish_reason(ShareType share, uint256 previous_block, uint32_t bits, const std::map<uint256, coind::data::tx_type> &known_txs);
};

