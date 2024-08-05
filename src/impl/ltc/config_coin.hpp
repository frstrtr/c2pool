#pragma once

#include <core/config.hpp>
#include <core/fileconfig.hpp>
#include <core/netaddress.hpp>

#include <yaml-cpp/yaml.h>

namespace ltc
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
} // namespace ltc

namespace YAML 
{
template<> struct convert<ltc::config::P2PData> 
{
    static Node encode(const ltc::config::P2PData& rhs) 
    {
        Node node;
        node["prefix"] = HexStr(rhs.prefix);
        node["address"] = rhs.address;
        return node;
    }

    static bool decode(const Node& node, ltc::config::P2PData& rhs)
    {
        // prefix
        rhs.prefix = ParseHexBytes(node["prefix"].as<std::string>());
        // address
        rhs.address = node["address"].as<NetService>();
        return true;
    }
};

template<> struct convert<ltc::config::RPCData> 
{
    static Node encode(const ltc::config::RPCData& rhs)
    {
        Node node;
        node["address"] = rhs.address;
        node["userpass"] = rhs.userpass;
        return node;
    }

    static bool decode(const Node& node, ltc::config::RPCData& rhs)
    {
        rhs.address = node["address"].as<NetService>();
        rhs.userpass = node["userpass"].as<std::string>();
        return true;
    } 
};
}

namespace ltc
{
    
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

    int m_share_period{};
    // std::string symbol;
    // std::string coin_prefix; //TODO: const unsigned char*? + int identifier lenght
    // int32_t block_period;
    // std::string p2p_address;
    // int p2p_port
    // int address_vesion;
    // int address_p2sh_version;
    // int rpc_port;

    // uint256 dumb_scrypt_diff;
};

} // namespace ltc
