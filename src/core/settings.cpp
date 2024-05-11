#include "settings.hpp"

#include <core/filesystem.hpp>

#include <yaml-cpp/yaml.h>

std::string c2pool::settings::get_default()
{
    YAML::Emitter out;

    out << YAML::BeginMap;
    out << YAML::Key << "testnet" << YAML::Value << false;
    out << YAML::Key << "networks" << YAML::BeginSeq << "<network_name>" << YAML::Comment("CHANGE IT!") << YAML::EndSeq;
    out << YAML::Key << "fee" << YAML::Value << 0;
    out << YAML::EndMap;
    // for (const auto& network : networks)
    //  << YAML::EndSeq;

    std::string result(out.c_str());
    return result;
}

#define PARSE_CONFIG(field, type)  \
    if (data[#field])      \
        result->m_##field = data[#field].as<type>();

c2pool::settings* c2pool::settings::load()
{
    YAML::Node data = YAML::LoadFile(filesystem::config_path() / default_filename);
    c2pool::settings* result = new c2pool::settings();
        
    PARSE_CONFIG(testnet, bool);
    PARSE_CONFIG(networks, std::vector<std::string>);
    PARSE_CONFIG(fee, float);

    return result;
}
#undef parse

void c2pool::settings::parse_networks()
{
    for (const auto& net : m_networks)
    {
        
    }
}
