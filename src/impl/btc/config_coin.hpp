// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

#include <core/config.hpp>
#include <core/fileconfig.hpp>
#include <core/netaddress.hpp>
#include <core/address_utils.hpp>   // core::CoinAddressAcceptance (issue #961)
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

// Registry-sourced payout-address acceptance for BTC on the ACTIVE network
// (issue #961). Bitcoin Core chainparams.cpp: mainnet PUBKEY_ADDRESS=0 /
// SCRIPT_ADDRESS=5 / bech32 "bc"; testnet & regtest both PUBKEY_ADDRESS=111 /
// SCRIPT_ADDRESS=196, with bech32 "tb" (testnet) vs "bcrt" (regtest). Deriving
// the set from the true network — not a mainnet-or-not bool — is what keeps a
// --regtest address from being rejected as Foreign (blocker #2), and centralises
// the version bytes out of the stratum money path (blocker #3).
inline core::CoinAddressAcceptance address_acceptance(bool testnet, bool regtest)
{
    core::CoinAddressAcceptance a;
    if (testnet || regtest) {
        a.p2pkh_versions = { 0x6f };  // 111 (m/n...)
        a.p2sh_versions  = { 0xc4 };  // 196 (2...)
        a.bech32_hrps    = { regtest ? "bcrt" : "tb" };
    } else {
        a.p2pkh_versions = { 0x00 };  // 1...
        a.p2sh_versions  = { 0x05 };  // 3...
        a.bech32_hrps    = { "bc" };
    }
    return a;
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