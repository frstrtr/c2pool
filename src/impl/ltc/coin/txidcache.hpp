#pragma once

#include <map>
#include <string>
#include <mutex>
#include <shared_mutex>

#include <core/uint256.hpp>
#include <core/common.hpp>

namespace ltc
{
    
namespace coin
{

class TXIDCache
{
    using key_t = std::string;

    mutable std::shared_mutex m_mutex;
	bool m_started {false};
	time_t m_when_started{0};

	std::map<key_t, uint256> m_cache; //getblocktemplate.transacions[].data; hash256(packed data)

public:

    void start()
    {
        std::shared_lock lock(m_mutex);
        m_when_started = core::timestamp();
        m_started = true;
    }

    bool exist(const key_t& key) const 
    {
        std::shared_lock lock(m_mutex);
        return m_cache.contains(key);
    }

    bool is_started() const 
    {
        std::shared_lock lock(m_mutex);
        return m_started; 
    }

    bool time() const 
    {
        std::shared_lock lock(m_mutex);
        return m_when_started; 
    }

    void clear() 
    {
        std::unique_lock lock(m_mutex);
        m_cache.clear(); 
    }

    void add(const key_t& key, const uint256& value)
    {
        std::unique_lock lock(m_mutex);
        m_cache[key] = value;
    }

    void add(std::map<key_t, uint256> values)
    {
        std::unique_lock lock(m_mutex);
        m_cache.insert(values.begin(), values.end());
    }

    uint256 get(const key_t& key)
    {
        std::shared_lock lock(m_mutex);

        if (m_cache.contains(key))
            return m_cache[key];
        else
            throw std::out_of_range("key not found in TXIDCache!");
    }
    
};

} // namespace coin

} // namespace ltc
