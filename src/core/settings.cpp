#include "settings.hpp"

#include <core/filesystem.hpp>

#include <yaml-cpp/yaml.h>

std::string c2pool::settings::get_default()
{
    YAML::Emitter out;

    out << YAML::BeginMap;
    out << YAML::Key << "testnet" << YAML::Value << false;
    out << YAML::Key << "networks" << YAML::BeginSeq << "default_network" << YAML::Comment("template network") << YAML::EndSeq;
    out << YAML::Key << "fee" << YAML::Value << 0;
    out << YAML::EndMap;
    // for (const auto& network : networks)
    //  << YAML::EndSeq;

    std::string result(out.c_str());
    return result;
}



void c2pool::settings::load()
{
    YAML::Node node = YAML::LoadFile(filesystem::config_path() / default_filename);
    
    PARSE_CONFIG(node, testnet, bool);
    PARSE_CONFIG(node, networks, std::vector<std::string>);
    PARSE_CONFIG(node, fee, float);

    for (const auto& network : m_networks)
    {
        parse_network_config(network, node);
    }
}

void c2pool::settings::parse_network_config(std::string name, YAML::Node& node)
{
    // auto net_node = node[network];
    
    // PARSE_CONFIG(net_node, arg, bool);
}
