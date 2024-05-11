#pragma once

#include <string>
#include <vector>

#include <core/fileconfig.hpp>

namespace c2pool
{

namespace pool
{
    class config : c2pool::fileconfig
    {
        static constexpr const char* default_filename = "config.yaml";

    public:
        bool m_testnet;
        std::vector<std::string> m_networks;
        float m_fee;

        static std::string get_default();
        static c2pool::pool::config* load();

    };
} // namespace pool

namespace coin
{
    class config : c2pool::fileconfig
    {
        static constexpr const char* default_filename = "coin.yaml";

    public:
        std::string get_default();
        void load();

    };
} // namespace coin

class config
{
public:
    std::string m_net_name;
    std::string m_symbol;

    c2pool::pool::config* pool;
    c2pool::coin::config* coin;

    static c2pool::config* load(std::string net_name);
};

} // namespace c2pool
