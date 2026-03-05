#include "config_pool.hpp"

#include <btclibs/util/strencodings.h>
#include <yaml-cpp/yaml.h>

namespace ltc
{

std::ofstream& PoolConfig::get_default(std::ofstream& file)
{
    YAML::Node out;
    
    // Use the canonical LTC p2pool mainnet prefix when no prefix is set yet
    out["prefix"] = m_prefix.empty() ? DEFAULT_PREFIX_HEX : HexStr(m_prefix);
    out["worker"] = m_worker;

    YAML::Node addrs_node;
    for (const auto& host : DEFAULT_BOOTSTRAP_HOSTS)
        addrs_node.push_back(host + ":" + std::to_string(P2P_PORT));
    out["bootstrap_addrs"] = addrs_node;

    file << out;
    return file;
}

void PoolConfig::load()
{
    YAML::Node node = YAML::LoadFile(m_filepath.string());
    
    // prefix
    m_prefix = ParseHexBytes(node["prefix"].as<std::string>());
    
    PARSE_CONFIG(node, worker, std::string);

    // Bootstrap addresses: load from YAML if present, otherwise use hardcoded defaults
    if (node["bootstrap_addrs"] && node["bootstrap_addrs"].IsSequence())
    {
        for (const auto& item : node["bootstrap_addrs"])
            m_bootstrap_addrs.emplace_back(item.as<std::string>());
    }
    else
    {
        for (const auto& host : DEFAULT_BOOTSTRAP_HOSTS)
            m_bootstrap_addrs.emplace_back(host + ":" + std::to_string(P2P_PORT));
    }
}

} // namespace ltc
