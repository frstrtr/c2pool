#pragma once

#include <map>
#include <string>

#include <core/uint256.hpp>
#include <core/common.hpp>

namespace ltc
{
    
namespace coin
{

class TXIDCache
{
    using key_t = std::string;

	bool m_started {false};
	time_t m_when_started{0};

	std::map<key_t, uint256> m_cache; //getblocktemplate.transacions[].data; hash256(packed data)

public:

    void start()
    {
        m_when_started = core::timestamp();
        m_started = true;
    }

    bool exist(const key_t& key) const {return m_cache.contains(key);}
    bool is_started() const { return m_started; }
    bool time() const { return m_when_started; }
    void clear() { m_cache.clear(); }

    void add(const key_t& key, const uint256& value)
    {
        m_cache[key] = value;
    }

    void add(std::map<key_t, uint256> values)
    {
        m_cache.insert(values.begin(), values.end());
    }

    uint256 get(const key_t& key)
    {
        if (exist(key))
            return m_cache[key];
        else
            return uint256::ZERO; // or throw invalid_argument
    }
    
};

} // namespace coin

} // namespace ltc
