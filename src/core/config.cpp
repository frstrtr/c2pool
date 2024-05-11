#include "config.hpp"

namespace c2pool
{

Config* Config::load(const std::string& coin_name)
{
    Config* config = new c2pool::Config(coin_name);
    // pool
    pool::Config* pool = config;
    pool->init();

    // coin
    coin::Config* coin = config;
    coin->init();

    return config;
}

}