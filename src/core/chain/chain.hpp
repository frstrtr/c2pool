#pragma once
#include <map>
#include <set>
#include <vector>

#include <btclibs/uint256.h>

namespace c2pool
{

namespace core
{

struct ChainSum
{

};

template <typename ItemT, typename SumT>
struct ChainRule
{
    using item_t = ItemT;
    using hash_t = typename value_t::hash_t;
    using sum_t = SumT;

    template <typename... Args>
    sum_t make_sum(Args... args)
    {
        return sum_t{args...};
    }
};

template <typename Rule>
class Chain
{
public:
    using rule_t = Rule;
    using hash_t = typename rule_t::hash_t;
    using item_t = typename rule_t::item_t;
    using sum_t = typename rule_t::sum_t;

    using it_items = typename std::map<hash_t, item_t>::iterator;
    // using fork_type = Fork
    
protected:
    std::map<hash_t, item_t> m_items;
    // std::map<hash_t, std::vector<it_items>> reverse;

    // std::vector<fork_ptr> forks;
    // std::map<hash_t, fork_ptr> fork_by_key;


public:
    explicit Chain() {}

    template <typename ValueT>
    void add(ValueT&& value)
    {
        // m_items[key] = 
        m_items.emplace()
    }

    void remove(hash_t&& key);
    item_t get_item(hash_t hash) const;
    bool exist(hash_t&& hash);
    sum_to_last get_sum_to_last(hash_t hash);
    sum_element get_sum_for_element(const hash_t& hash);
    int32_t get_height(hash_t&& hash);
    hash_type get_last(hash_t&& hash);
    height_and_last get_height_and_last(hash_t&& item);
    bool is_child_of(hash_t&& item, hash_t&& possible_child);
    hash_type get_nth_parent_key(hash_t&& hash, int32_t n) const;
    std::function<bool(hash_type&)> get_chain(hash_t&& hash, uint64_t n)
    sum_element get_sum(hash_type item, hash_type ancestor)

};

} // namespace core

} // namespace c2pool
