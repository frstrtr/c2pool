#pragma once

#include <string>
#include <vector>
#include <set>

#include <core/uint256.hpp>
#include <core/fileconfig.hpp>

#include <core/configs/pool.hpp>
#include <core/configs/coin.hpp>

namespace core
{

class Config : public pool::Config, public coin::Config
{
public:
    std::string m_name;

    Config(const std::string& name) : pool::Config(name), coin::Config(name)
    {

    }

    static core::Config* load(const std::string& coin_name);
};

} // namespace core
