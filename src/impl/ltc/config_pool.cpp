#include "config_pool.hpp"

#include <btclibs/util/strencodings.h>
#include <yaml-cpp/yaml.h>

namespace ltc
{

std::ofstream& PoolConfig::get_default(std::ofstream& file)
{
    YAML::Node out;
    
    out["prefix"] = HexStr(m_prefix);
    out["worker"] = m_worker;

    file << out;
    return file;
}

void PoolConfig::load()
{
    YAML::Node node = YAML::LoadFile(m_filepath.string());
    
    // prefix
    m_prefix = ParseHexBytes(node["prefix"].as<std::string>());
    
    PARSE_CONFIG(node, worker, std::string);
}

} // namespace ltc
