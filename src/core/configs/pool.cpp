#include "pool.hpp"

#include <core/filesystem.hpp>
#include <yaml-cpp/yaml.h>

namespace c2pool
{

namespace pool
{

std::string Config::get_default()
{
    YAML::Emitter out;
    out << YAML::BeginMap;
    {
        out << YAML::Key << "worker" << YAML::Value << m_worker;
    }
    out << YAML::EndMap;

    return std::string(out.c_str());
}

void Config::load()
{
    YAML::Node node = YAML::LoadFile(m_filepath.string());
    
    PARSE_CONFIG(node, worker, std::string);
}

} // namespace pool

} // namespace c2pool