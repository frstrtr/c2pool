#pragma once
#include <map>
// #include <unordered_map>
#include <set>
#include <vector>

// TODO:

namespace c2pool
{

namespace core
{

template <typename KeyT, typename ValueT>
struct BaseChainRule
{
    using key_type = KeyT;
    using value_type = ValueT;

};

template <typename Rule>
class Chain
{
public:
    using rule_type = Rule;
    using key_type = typename rule_type::key_type;
    using value_type = typename rule_type::value_type;
    
protected:
    std::map<key_type, value_type> values;
    
public:
    explicit Chain() {}

    void add(value_type&& value)
    {
        
    }

    void remove(const key_type&& key)
    {

    }

};

} // namespace core

} // namespace c2pool
