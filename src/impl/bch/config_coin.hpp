// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once
// bch::CoinConfig -- BCH coin parameters (V36). Ported from
// src/impl/btc/config_coin.hpp (M3 slice 14). Namespace bch (was the M2
// skeleton's c2pool::bch CoinParams -- reconciled to bch::CoinConfig here so
// config.hpp's core::Config<PoolConfig, CoinConfig> resolves; see the M3
// slice-1 namespace note).
//
// SCOPE NOTE (M1 4.2): HogEx is a SmartBCH sidechain construct, NOT BCH
// mainchain. It is explicitly OUT OF SCOPE for this coin module. Do not add
// HogEx commitment handling here. See feedback: hogex-not-bch.
//
// CashAddr: BCH address encoding diverges from BTC base58/bech32. The codec
// (prefix "bitcoincash:"/"bchtest:"/"bchreg:", base32 + BCH-code PolyMod
// checksum, CashTokens z/r token-aware types, P2SH32) lives in
// coin/cashaddr.hpp -- {type,hash} <-> string, operator/payout-address layer.
// The wire/config shape below stays coin-agnostic and matches the btc
// reference 1:1 (P2P prefix + NetService + RPC userpass).

#include <core/config.hpp>
#include <core/fileconfig.hpp>
#include <core/netaddress.hpp>
#include <core/address_utils.hpp>   // core::CoinAddressAcceptance (issue #961)

#include <yaml-cpp/yaml.h>

namespace bch
{

// Registry-sourced LEGACY-base58 payout-address acceptance for BCH on the ACTIVE
// network (issue #961). BCH legacy base58 shares Bitcoin's version bytes
// (BCHN chainparams.cpp): mainnet PUBKEY 0 / SCRIPT 5; testnet & regtest both
// PUBKEY 111 / SCRIPT 196. BCH has NO segwit/bech32 — its native CashAddr is a
// DISTINCT format with no base58 version byte, so a CashAddr yields
// AddressCoinMatch::Invalid here and (only then) falls through to the
// coin-registered CashAddr decoder. Deriving from the true network keeps a
// --regtest legacy address from being rejected as Foreign.
inline core::CoinAddressAcceptance address_acceptance(bool testnet, bool regtest)
{
    core::CoinAddressAcceptance a;
    if (testnet || regtest) {
        a.p2pkh_versions = { 0x6f };  // 111
        a.p2sh_versions  = { 0xc4 };  // 196
    } else {
        a.p2pkh_versions = { 0x00 };
        a.p2sh_versions  = { 0x05 };
    }
    a.bech32_hrps = {};               // BCH: no bech32 (CashAddr via fallback)
    return a;
}

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
} // namespace bch

namespace YAML
{
template<> struct convert<bch::config::P2PData>
{
    static Node encode(const bch::config::P2PData& rhs)
    {
        Node node;
        node["prefix"] = HexStr(rhs.prefix);
        node["address"] = rhs.address;
        return node;
    }

    static bool decode(const Node& node, bch::config::P2PData& rhs)
    {
        // prefix
        rhs.prefix = ParseHexBytes(node["prefix"].as<std::string>());
        // address
        rhs.address = node["address"].as<NetService>();
        return true;
    }
};

template<> struct convert<bch::config::RPCData>
{
    static Node encode(const bch::config::RPCData& rhs)
    {
        Node node;
        node["address"] = rhs.address;
        node["userpass"] = rhs.userpass;
        return node;
    }

    static bool decode(const Node& node, bch::config::RPCData& rhs)
    {
        rhs.address = node["address"].as<NetService>();
        rhs.userpass = node["userpass"].as<std::string>();
        return true;
    }
};
}

namespace bch
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

    std::string m_symbol;
    int m_share_period{};
    bool m_testnet {false};
    bool m_testnet4 {false};  // BCH testnet4: OWN genesis (000000001dd4..) + magic e2b7daaf; testnet-class for ABLA/ASERT
};

} // namespace bch