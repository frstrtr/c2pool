#include "config_coin.hpp"

#include <btclibs/util/strencodings.h>

namespace ltc
{

std::ofstream& CoinConfig::get_default(std::ofstream& file)
{
    YAML::Node out;
    
    out["p2p"] = config::P2PData();
    out["rpc"] = config::RPCData();
    out["share_period"] = 0;

    file << out;
    return file;
}

void CoinConfig::load()
{
    YAML::Node node = YAML::LoadFile(m_filepath.string());
        
    m_p2p = node["p2p"].as<config::P2PData>();
    m_rpc = node["rpc"].as<config::RPCData>();

    PARSE_CONFIG(node, share_period, int);
}

} // namespace ltc
