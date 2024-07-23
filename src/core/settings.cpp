#include "settings.hpp"

#include <core/filesystem.hpp>

#include <yaml-cpp/yaml.h>

namespace core
{

std::string Settings::get_default()
{
    YAML::Emitter out;
    out << YAML::BeginMap;
    {
        out << YAML::Key << "testnet" << YAML::Value << false;
        out << YAML::Key << "networks" << YAML::BeginSeq << "default_network" << YAML::Comment("template network") << YAML::EndSeq;
        out << YAML::Key << "fee" << YAML::Value << 0;
    }
    out << YAML::EndMap;

    return std::string(out.c_str());
}

void Settings::load()
{
    YAML::Node node = YAML::LoadFile(m_filepath.string());
    
    PARSE_CONFIG(node, testnet, bool);
    PARSE_CONFIG(node, networks, std::vector<std::string>);
    PARSE_CONFIG(node, fee, float);
}

} // namespace core