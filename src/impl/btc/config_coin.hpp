// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

#include <core/config.hpp>
#include <core/fileconfig.hpp>
#include <core/netaddress.hpp>
#include <string>

#include <yaml-cpp/yaml.h>

namespace btc
{
namespace config
{
    struct P2PData
    {
        std::vector<std::byte> prefix;
        NetService address;
    };

    struct RPCData
    {
        NetService address;
        std::string userpass;
    };

} // config
} // namespace btc

namespace YAML 
{
template<> struct convert<btc::config::P2PData> 
{
    static Node encode(const btc::config::P2PData& rhs) 
    {
        Node node;
        node["prefix"] = HexStr(rhs.prefix);
        node["address"] = rhs.address;
        return node;
    }

    static bool decode(const Node& node, btc::config::P2PData& rhs)
    {
        // prefix
        rhs.prefix = ParseHexBytes(node["prefix"].as<std::string>());
        // address
        rhs.address = node["address"].as<NetService>();
        return true;
    }
};

template<> struct convert<btc::config::RPCData> 
{
    static Node encode(const btc::config::RPCData& rhs)
    {
        Node node;
        node["address"] = rhs.address;
        node["userpass"] = rhs.userpass;
        return node;
    }

    static bool decode(const Node& node, btc::config::RPCData& rhs)
    {
        rhs.address = node["address"].as<NetService>();
        rhs.userpass = node["userpass"].as<std::string>();
        return true;
    } 
};
}

namespace btc
{

// Sharechain LevelDB + P2P-listen namespace isolation.
//
// regtest MUST be evaluated FIRST: main_btc resets CoinConfig::m_testnet to
// false under --regtest (it drives only the parent chainparams), so a
// testnet-only switch would resolve to "bitcoin" = MAINNET and silently join
// the production p2pool sharechain -- the .121 standup incident of
// 2026-06-26, where a won regtest block would have relayed to real peers.
// Pure free function so the isolation invariant is lockable without standing
// up a node. Locked by regtest_sharechain_isolation_test.cpp.
inline std::string sharechain_net_name(bool regtest, bool testnet)
{
    if (regtest) return "bitcoin_regtest";
    if (testnet) return "bitcoin_testnet";
    return "bitcoin";
}

class CoinConfig : protected core::Fileconfig
{

protected:
    std::ofstream& get_default(std::ofstream& file) override;
    void load() override;

public:
    CoinConfig(const std::filesystem::path& path) : core::Fileconfig(path)
    {

    }

public:
    
    config::P2PData m_p2p;
    config::RPCData m_rpc;

    std::string m_symbol;
    int m_share_period{};
    bool m_testnet {false};
    bool m_regtest {false};  // --regtest: isolated sharechain net namespace (bitcoin_regtest)
    // std::string coin_prefix; //TODO: const unsigned char*? + int identifier lenght
    // int32_t block_period;
    // std::string p2p_address;
    // int p2p_port
    // int address_vesion;
    // int address_p2sh_version;
    // int rpc_port;

    // uint256 dumb_scrypt_diff;
};

} // namespace btc