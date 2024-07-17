#include "coin.hpp"

#include <yaml-cpp/yaml.h>

namespace coin
{

std::string Config::get_default()
{
    YAML::Emitter out;
    out << YAML::BeginMap;
    {
        out << YAML::Key << "share_period" << YAML::Value << m_share_period;
    }
    out << YAML::EndMap;

    return std::string(out.c_str());
}

void Config::load()
{
    YAML::Node node = YAML::LoadFile(m_filepath.string());
    
    PARSE_CONFIG(node, share_period, int);
}

} // namespace coin