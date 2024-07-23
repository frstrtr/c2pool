#include "config.hpp"

#include <btclibs/util/strencodings.h>
#include <yaml-cpp/yaml.h>

namespace ltc
{

// Pool
std::string PoolConfig::get_default()
{
    YAML::Emitter out;
    out << YAML::BeginMap;
    {
        out << YAML::Key << "prefix" << YAML::Value << HexStr(m_prefix);
        out << YAML::Key << "worker" << YAML::Value << m_worker;
    }
    out << YAML::EndMap;

    return std::string(out.c_str());
}

void PoolConfig::load()
{
    YAML::Node node = YAML::LoadFile(m_filepath.string());
    
    // prefix
    auto prefix = ParseHexBytes(node["prefix"].as<std::string>());
    m_prefix.insert(m_prefix.begin(), prefix.begin(), prefix.end());
    PARSE_CONFIG(node, worker, std::string);
}

// Coin
std::string CoinConfig::get_default()
{
    YAML::Emitter out;
    out << YAML::BeginMap;
    {
        out << YAML::Key << "share_period" << YAML::Value << m_share_period;
    }
    out << YAML::EndMap;

    return std::string(out.c_str());
}

void CoinConfig::load()
{
    YAML::Node node = YAML::LoadFile(m_filepath.string());
    
    PARSE_CONFIG(node, share_period, int);
}


} // namespace ltc
