#pragma once

#include <string>
#include <vector>
#include <set>

#include <btclibs/uint256.h>
#include <core/fileconfig.hpp>

#include <core/configs/pool.hpp>
#include <core/configs/coin.hpp>

namespace c2pool
{

class Config : public c2pool::pool::Config, public c2pool::coin::Config
{
public:
    std::string m_name;

    Config(const std::string& name) : pool::Config(name), coin::Config(name)
    {

    }

    static c2pool::Config* load(const std::string& coin_name);
};

} // namespace c2pool
