#pragma once

#include <string>
#include <vector>
#include <set>

#include <core/uint256.hpp>
#include <core/fileconfig.hpp>

namespace core
{

template <typename Pool, typename Coin>
class Config : public Pool, public Coin
{
    static_assert(std::is_base_of_v<core::Fileconfig, Pool> && std::is_base_of_v<core::Fileconfig, Coin>);
    static constexpr const char* pool_filename = "pool.yaml";
    static constexpr const char* coin_filename = "coin.yaml";

public:
    std::string m_name;
    std::filesystem::path m_path;

    Config(const std::string& coin_name) 
        : m_name(coin_name), m_path(core::filesystem::config_path() / m_name),
            Pool(m_path / pool_filename), Coin(m_path / coin_filename) 
    { 

    }

    static core::Config<Pool, Coin>* load(const std::string& coin_name)
    {
        auto* config = new core::Config<Pool, Coin>(coin_name);
        // pool
        Pool* pool = config;
        pool->init();

        // coin
        Coin* coin = config;
        coin->init();

        return config;
    }
};

} // namespace core
