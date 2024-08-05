#include "settings.hpp"

#include <core/filesystem.hpp>

#include <yaml-cpp/yaml.h>

namespace core
{

std::ofstream& Settings::get_default(std::ofstream& file)
{
    YAML::Node out;
    
    out["testnet"] = false;
    out["networks"] = std::vector<std::string>{"default_network"};
    out["fee"] = 0;

    file << out;
    return file;
}

void Settings::load()
{
    YAML::Node node = YAML::LoadFile(m_filepath.string());
    
    PARSE_CONFIG(node, testnet, bool);
    PARSE_CONFIG(node, networks, std::vector<std::string>);
    PARSE_CONFIG(node, fee, float);
}

} // namespace core