#pragma once

// Dash configuration types.

#include <core/config.hpp>
#include <core/fileconfig.hpp>
#include <core/netaddress.hpp>

#include <string>
#include <vector>

namespace dash
{

// Dash pool config (loaded from YAML)
class PoolConfig : protected core::Fileconfig
{
protected:
    std::ofstream& get_default(std::ofstream& file) override { return file; }
    void load() override {}

public:
    PoolConfig(const std::filesystem::path& path) : core::Fileconfig(path) {}

    std::vector<std::byte> m_prefix;
    std::string m_worker;
    std::vector<NetService> m_bootstrap_addrs;
};

// Dash coin config (RPC/P2P endpoints)
class CoinConfig : protected core::Fileconfig
{
protected:
    std::ofstream& get_default(std::ofstream& file) override { return file; }
    void load() override {}

public:
    CoinConfig(const std::filesystem::path& path) : core::Fileconfig(path) {}

    bool m_testnet{false};

    struct P2PData {
        std::vector<std::byte> prefix;
        NetService address;
    } m_p2p;

    struct RPCData {
        NetService address;
        std::string userpass;
    } m_rpc;
};

// Combined config
using Config = core::Config<PoolConfig, CoinConfig>;

} // namespace dash
