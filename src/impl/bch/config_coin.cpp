// SPDX-License-Identifier: AGPL-3.0-or-later
#include "config_coin.hpp"

#include <btclibs/util/strencodings.h>

// bch::CoinConfig load/default -- ported from src/impl/btc/config_coin.cpp
// (M3 slice 15). Coin-agnostic in shape; the BCH-specific parameter values are
// supplied by the on-disk YAML and the bch::config types in config_coin.hpp.

namespace bch
{

std::ofstream& CoinConfig::get_default(std::ofstream& file)
{
    YAML::Node out;

    out["symbol"] = "defaultNet";
    out["p2p"] = config::P2PData();
    out["rpc"] = config::RPCData();
    out["share_period"] = 0;
    out["testnet"] = false;

    file << out;
    return file;
}

void CoinConfig::load()
{
    YAML::Node node = YAML::LoadFile(m_filepath.string());

    PARSE_CONFIG(node, symbol, std::string);

    m_p2p = node["p2p"].as<config::P2PData>();
    m_rpc = node["rpc"].as<config::RPCData>();

    PARSE_CONFIG(node, share_period, int);
    PARSE_CONFIG(node, testnet, bool);
}

} // namespace bch