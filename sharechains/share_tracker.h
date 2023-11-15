#pragma once

#include <memory>

#include "base_share_tracker.h"
#include "share_store.h"
#include <web_interface/metrics/metric_macro_scope.h>
#include <web_interface/metrics.hpp>

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

struct PreparedList
{
    typedef std::string hash_type;
    typedef ShareType item;

    //last->(prev->value)->best
    struct PreparedNode
    {
        item value{};
        PreparedNode *prev_node{};
        std::set<PreparedNode *> next_nodes;

#ifdef DEBUG_TRACKER
        std::string _hash;
        std::string _prev_hash;
#endif

        PreparedNode()
        {}

        explicit PreparedNode(item val) : value(val)
        {
#ifdef DEBUG_TRACKER
            _hash = hash();//.ToString();
            _prev_hash = prev_hash();//.ToString();
#endif
        };


        hash_type hash() const
        {
            return value->hash.ToString();
        }

        hash_type prev_hash() const
        {
            return (*value->previous_hash).ToString();
        }
    };

    std::map<hash_type, std::set<PreparedNode *>> branch_tails; // value.previous_hash -> value
    std::map<hash_type, PreparedNode *> nodes;

    PreparedNode *make_node(const item &val)
    {
        auto node = new PreparedNode(val);
        nodes[node->hash()] = node;

        return node;
    }

    static PreparedNode *merge_nodes(PreparedNode *n1, PreparedNode *n2)
    {
        if (n1->hash() == n2->prev_hash())
        {
            n1->next_nodes.insert(n2);
            n2->prev_node = n1;
            return n1;
        } else if (n2->hash() == n1->prev_hash())
        {
            n2->next_nodes.insert(n1);
            n1->prev_node = n2;
            return n1;
        }

        throw std::invalid_argument("can't merge nodes");
    }

    void add(std::vector<item> values)
    {
        // temp-data
        std::map<hash_type, std::vector<item>::iterator> items; // hash->item;
        std::map<hash_type, std::vector<std::vector<item>::iterator>> tails; // хэши, которые являются предыдущими существующим item's.

        for (auto it = values.begin(); it != values.end(); it++)
        {
            items[(*it)->hash.ToString()] = it;
            tails[(*it)->previous_hash->ToString()].push_back(it);
        }

        // generate branches
        while (!items.empty())
        {
            // get element from hashes
            auto [hash, value] = *items.begin();
            items.erase(hash);

            PreparedNode *head = make_node(*value);
            PreparedNode *tail = nullptr;
            if (items.count(head->prev_hash()))
            {
                tail = make_node(*items[head->prev_hash()]);
                merge_nodes(tail, head);
                items.erase(head->prev_hash());
            }


            // generate left part of branch
            while (tail && items.count(tail->prev_hash()))
            {
                PreparedNode *new_tail = make_node(*items[tail->prev_hash()]);
                merge_nodes(new_tail, tail);
                items.erase(tail->prev_hash());
                tail = new_tail;
            }

            // generate right part of branch
            while (tails.count(head->hash()))
            {
                PreparedNode *merged_head = nullptr;
                for (auto _head: tails[head->hash()])
                {
                    PreparedNode *new_head = make_node(*_head);
//                    branch_heads[new_head->value.hash].insert(new_head);
                    merged_head = merge_nodes(new_head, head);
                    items.erase(new_head->hash());
                }
                head = merged_head;
            }

            if (tail)
            {
                branch_tails[tail->prev_hash()].insert(tail); // update branch_tails for new tail
            } else
            {
                PreparedNode *new_tail = head;
                while (new_tail->prev_node)
                {
                    new_tail = new_tail->prev_node;
                }

                branch_tails[new_tail->prev_hash()].insert(new_tail);
            }
        }

        //check for merge branch
        // -- heads
        std::set<hash_type> keys_remove;
        for (auto &[k, v]: branch_tails)
        {
            if (nodes.count(k))
            {
                for (auto _tail: v)
                {
                    merge_nodes(nodes[k], _tail);
                }
                keys_remove.insert(k);
            }
        }
        for (auto k : keys_remove){
            branch_tails.erase(k);
        }
    }

    void update_stack(PreparedNode* node, std::stack<PreparedNode*>& st)
    {
        st.push(node);

        if (!node->next_nodes.empty())
        {
            for (const auto &next : node->next_nodes)
                update_stack(next, st);
        }
    }

    auto build_list()
    {
        std::stack<PreparedNode*> st;
        for (const auto &branch : branch_tails)
        {
            for (auto node : branch.second)
            {
//                st.push(node);
                update_stack(node, st);
            }
        }

        std::vector<item> result;
        while (!st.empty())
        {
            result.push_back(st.top()->value);
            st.pop();
        }

        return result;
    };
};

struct desired_type
{
    NetAddress peer_addr;
    uint256 hash;
    uint32_t timestamp;
    uint256 target;

    friend bool operator<(const desired_type& l, const desired_type& r)
    {
        return std::tie(l.peer_addr, l.hash, l.target, l.timestamp) < std::tie(r.peer_addr, r.hash, r.target, r.timestamp);
    }
};

template <typename score_type>
struct decorated_data
{
    score_type score;
    uint256 hash;

    friend inline bool operator<(const decorated_data<score_type>& a, const decorated_data<score_type>& b) { return a.score < b.score; }
};

struct tail_score
{
    int32_t chain_len{};
    uint288 hashrate;

    friend inline bool operator<(const tail_score& a, const tail_score& b) { return std::tie(a.chain_len, a.hashrate) < std::tie(b.chain_len, b.hashrate); }
};

struct head_score
{
    uint288 work;
    int32_t reason{};
    int32_t time_seen{};

    head_score() = default;
    head_score(uint288 _work, int32_t _reason, int32_t _time_seen) : work(std::move(_work)), reason(_reason), time_seen(_time_seen) { }
    head_score(uint256 _work, int32_t _reason, int32_t _time_seen) : reason(_reason), time_seen(_time_seen)
    {
        work.SetHex(_work.GetHex());
    }


    friend inline bool operator<(const head_score& a, const head_score& b)
    {
        if (a.work < b.work) return true;
        if (b.work < a.work) return false;
        return std::tie(a.reason, a.time_seen) > std::tie(b.reason, b.time_seen);
    }
};

struct traditional_score
{
    uint288 work;
    int32_t time_seen{};
    int32_t reason{};

    friend inline bool operator<(const traditional_score& a, const traditional_score& b)
    {
        if (a.work < b.work) return true;
        if (b.work < a.work) return false;
        return std::tie(a.time_seen, a.reason) > std::tie(b.time_seen, b.reason);
    }
};

struct punish_reason
{
    int punish;
    std::string reason;
};

struct TrackerThinkResult
{
    uint256 best;
    std::vector<std::tuple<NetAddress, uint256>> desired;
    std::vector<decorated_data<head_score>> decorated_heads;
    std::set<NetAddress> bad_peer_addresses;
    int punish_aggressively;
};

//---> Web Share Tracker

struct shares_stale_count
{
    uint288 good;
    uint288 doa;
    uint288 orphan;

    shares_stale_count operator/(const int& t) const
    {
        return shares_stale_count{good/t, doa/t, orphan/t};
    }

    CUSTOM_METRIC_DEFINE_TYPE_INTRUSIVE(shares_stale_count, good, doa, orphan);
};

class WebShareTracker
{
protected:
    //typedef MetricSum<shares_stale_count, 120> stale_counts_metric_type;
    typedef MetricParamGetter share_param_metric_type;
    typedef MetricGetter tracker_info_metric_type;
protected:
    // Metrics
    //stale_counts_metric_type* stale_counts_metric{};
    share_param_metric_type* share_param_metric{};
    tracker_info_metric_type* tracker_info_metric{};
protected:
    virtual void init_web_metrics() = 0;
};

//---> Share Tracker

class ShareTracker : public BaseShareTracker, protected WebShareTracker, public std::enable_shared_from_this<ShareTracker>
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
    void init_web_metrics() override;

    ShareType get(uint256 hash);
    nlohmann::json get_json(uint256 hash);

    void add(ShareType share) override;
    void remove(uint256 hash);

    bool attempt_verify(ShareType share);

    TrackerThinkResult think(const std::function<int32_t(uint256)>& block_rel_height_func, uint256 previous_block, uint32_t bits, std::map<uint256, coind::data::tx_type> known_txs);

    uint288 get_pool_attempts_per_second(uint256 previous_share_hash, int32_t dist, bool min_work = false);

    // returns approximate lower bound on chain's hashrate in the last CHAIN_LENGTH*15//16*SHARE_PERIOD time
    auto score(const uint256& share_hash, const std::function<int32_t(uint256)> &block_rel_height_func)
    {
        uint288 score_res;

        auto head_height = verified.get_height(share_hash);
        if (head_height < net->CHAIN_LENGTH)
        {
            return tail_score{head_height, score_res};
        }

        auto end_point = verified.get_nth_parent_key(share_hash, (net->CHAIN_LENGTH * 15) / 16);

        std::optional<int32_t> block_height;
        auto gen_verif_chain = verified.get_chain(end_point, net->CHAIN_LENGTH / 16);

        uint256 hash;
        while (gen_verif_chain(hash))
        {
            auto share = verified.get_item(hash);

            auto block_height_temp = block_rel_height_func(share->header->previous_block);
            if (!block_height.has_value())
            {
                block_height = block_height_temp;
            } else
            {
                if (block_height.value() < block_height_temp)
                {
                    block_height = block_height_temp;
                }
            }
        }

        score_res = verified.get_sum(share_hash, end_point).work /
                    ((-block_height.value() + 1) * parent_net->BLOCK_PERIOD);

        return tail_score{net->CHAIN_LENGTH, score_res};
    }

    std::map<uint64_t, uint256> get_desired_version_counts(uint256 best_share_hash, uint64_t dist)
    {
        std::map<uint64_t, uint288> _result;

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
        for (const auto& v : _result)
        {
            result[v.first] = convert_uint<uint256>(v.second);
        }
        return result;
    }

    std::tuple<std::map<std::vector<unsigned char>, uint288>, uint288, uint288>
    get_cumulative_weights(uint256 start, int32_t max_shares, const uint288& desired_weight)
    {
        std::string algh_steps = "gcw debug: "; // FOR DEBUG
        // Если start -- None/Null/0 шара.
        if (start.IsNull())
        {
            // 0
            LOG_INFO << algh_steps << "01";
            return {{}, {}, {}};
        }

        auto [start_height, last] = get_height_and_last(start);

        // Ограничиваем цепочку до размера max_shares.
        if (start_height > max_shares)
        {
            algh_steps += "1->";
            last = get_nth_parent_key(start, max_shares);
        }

        // Поиск desired_weight
        LOG_INFO << "desired_weight = " << desired_weight.ToString();
        auto limit = get_sum_to_last(start).sum.weight.total_weight >= desired_weight ? get_sum_to_last(start).sum.weight.total_weight - desired_weight : uint288();
        LOG_INFO << "LIMIT = " << limit.ToString();
//        LOG_INFO.stream() << "limit = " << limit.GetHex();
        auto cur = get_sum_to_last(start);
        auto next = get_sum_to_last(cur.sum.prev());
        std::optional<shares::weight::weight_data> extra_ending;

        while (cur.sum.hash() != last)
        {
            algh_steps += "2->";
//            LOG_INFO.stream() << "[" << cur.sum.hash() << "->" << cur.sum.prev() << "]: total_weight = " << cur.sum.weight.total_weight.GetHex() << "; donation_weight = " << cur.sum.weight.total_donation_weight.GetHex();
            if (limit == next.sum.weight.total_weight)
            {
                algh_steps += "2.1->";
                break;
            }

            if (limit > next.sum.weight.total_weight)
            {
                algh_steps += "2.2->";
                extra_ending = std::make_optional<shares::weight::weight_data>(cur.sum.share);
                break;
            }

            algh_steps += "2.3->";
//            for (auto [k, v]: cur.sum.weight.amount)
//            {
//                if (weights.find(k) != weights.end())
//                {
//                    algh_steps += "2.31->";
//                    weights[k] += v;
//                } else
//                {
//                    algh_steps += "2.32->";
//                    weights[k] = v;
//                }
//            }

            cur = next;
            if (exist(cur.sum.prev()))
            {
                algh_steps += "2.41->";
                next = get_sum_to_last(next.sum.prev());
            } else
            {
                algh_steps += "2.42->";
                break;
            }
        }

        // Если мы почти набрали предел и следующая шара переваливает по весу, то каждый воркер, указанный в этой шаре, будет эвивалентно процентно получать соответствующую ему долю.
        if (extra_ending.has_value())
        {
            algh_steps += "3->";
            LOG_INFO << "1result_sum = get_sum(" << start.ToString() << ", " << cur.sum.hash() << ")";
            auto result_sum = get_sum(start, cur.sum.hash());
            //weights
            auto weights = result_sum.weight.amount;
            //total weights
            auto total_weights = result_sum.weight.total_weight;
            //total donation weights
            auto total_donation_weights = result_sum.weight.total_donation_weight;

            LOG_INFO << "result_sum: weight = " << result_sum.weight << "; height = " << result_sum.height << "; work = " << result_sum.work.GetHex() << ", min_work = " << result_sum.min_work.GetHex();

            auto [_script, _weight] = *extra_ending->amount.begin();
            //TODO: test (если много воркеров, может происходить неправильное округление)
            std::pair<std::vector<unsigned char>, uint288> new_weight = {_script,
                                                                               (desired_weight - total_weights) /
                                                                               65535 * _weight /
                                                                               (extra_ending->total_weight / 65535)
            };

            if (weights.find(new_weight.first) != weights.end())
            {
                algh_steps += "3.1->";
                weights[new_weight.first] += new_weight.second;
            } else
            {
                algh_steps += "3.2->";
                weights[new_weight.first] = new_weight.second;
            }

            total_donation_weights += (desired_weight - total_weights)/65535*extra_ending->total_donation_weight/(extra_ending->total_weight/65535);
            total_weights = desired_weight;

            LOG_INFO << "extra_ending: total_weight = " << extra_ending->total_weight.ToString() << "; total_donation_weight = " << extra_ending->total_donation_weight.ToString();
            LOG_INFO << "extra_ending.amount: ";
            for (auto v : extra_ending->amount)
            {
                LOG_INFO << "\t\t" << PackStream(v.first) << ": " << v.second.ToString();
            }
            LOG_INFO << "new_weight: " << PackStream(new_weight.first) << ": " << new_weight.second.ToString();
            LOG_INFO << "desired_weight = " << desired_weight.ToString() << "; total_weights = " << total_weights.ToString() << "; total_weight2 = " << extra_ending->total_weight.ToString();
//            LOG_INFO << algh_steps << "02";
            LOG_INFO << "02";
            return std::make_tuple(weights, total_weights, total_donation_weights);
        } else
        {
            LOG_INFO << "2result_sum = get_sum(" << start.ToString() << ", " << cur.sum.hash();
            auto result_sum = get_sum(start, /*std::get<2>(prev)*/cur.sum.hash());
            //total weights
            auto total_weights = result_sum.weight.total_weight;
            //total donation weights
            auto total_donation_weights = result_sum.weight.total_donation_weight;

            LOG_INFO << "02";
//            LOG_INFO << algh_steps << "03";
            return std::make_tuple(result_sum.weight.amount, total_weights, total_donation_weights);
        }
    }

    // from p2pool::share
    std::vector<uint256> get_other_tx_hashes(ShareType share);

    std::vector<coind::data::tx_type> _get_other_txs(ShareType share, const std::map<uint256, coind::data::tx_type> &known_txs);

    punish_reason should_punish_reason(ShareType share, uint256 previous_block, uint32_t bits, const std::map<uint256, coind::data::tx_type> &known_txs);

    float get_average_stale_prop(uint256 share_hash, uint64_t lookbehind);

    std::map<std::vector<unsigned char>, double> get_expected_payouts(uint256 best_share_hash, uint256 block_target, uint64_t subsidy);
};