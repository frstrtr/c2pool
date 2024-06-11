#pragma once
#include <map>
#include <set>
#include <vector>

#include <btclibs/uint256.h>

namespace c2pool
{

namespace core
{

template <typename SHARE_TYPE>
struct ChainRule
{
    using value_type = SHARE_TYPE;

};

template <typename Rule>
class Chain
{
public:
    using rule_type = Rule;
    using hash_type = uint256; // typename rule_type::key_type;
    using value_type = typename rule_type::value_type;
    
protected:
    std::map<hash_type, value_type> values;
    
public:
    explicit Chain() {}

    void add(value_type&& value)
    {
        
    }

    void remove(const hash_type&& key)
    {

    }

};

} // namespace core

} // namespace c2pool
