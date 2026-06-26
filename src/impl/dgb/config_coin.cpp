#include "config_coin.hpp"

#include <btclibs/util/strencodings.h>

namespace dgb
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

    // Dev-only boot aid (off by default). Optional key — absent in every normal
    // and production config, so it cannot be silently inherited by a real
    // crossing-soak. Never weakens the gate on mainnet (see
    // dgb::coin::compute_required_softforks). Deliberately NOT emitted by
    // get_default(): you must consciously add it to opt in.
    if (node["dev_relax_algo_softforks"])
        m_dev_relax_algo_softforks = node["dev_relax_algo_softforks"].as<bool>();
}

} // namespace dgb
