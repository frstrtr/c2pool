#include "config.hpp"

namespace core
{

Config* Config::load(const std::string& coin_name)
{
    Config* config = new core::Config(coin_name);
    // pool
    pool::Config* pool = config;
    pool->init();

    // coin
    coin::Config* coin = config;
    coin->init();

    return config;
}

} // namespace core