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
    void init()
    {
        Pool::init();
        Coin::init();
    }

public:
    std::string m_name;
    std::filesystem::path m_path;

    Config(const std::string& coin_name) 
        : m_name(coin_name), m_path(core::filesystem::config_path() / m_name),
            Pool(core::filesystem::config_path() / coin_name / pool_filename), Coin(core::filesystem::config_path() / coin_name / coin_filename) 
    { 
    }

    Pool* pool() { return (Pool*)this;}
    Coin* coin() { return (Coin*)this;}

    static core::Config<Pool, Coin>* load(const std::string& coin_name)
    {
        auto* config = new core::Config<Pool, Coin>(coin_name);
        config->init();
        return config;
    }
};

} // namespace core
