#pragma once

#include <vector>
#include <string>
#include <map>

#include <core/config.hpp>
#include <core/fileconfig.hpp>

namespace YAML
{
    class Node;
}

namespace core
{

class Settings : public Fileconfig
{
    static constexpr const char* default_filename = "settings.yaml";

private:
    void parse_network_config(std::string name, YAML::Node& node);

protected:
    std::string get_default() override;
    void load() override;

public:
    Settings() 
        : core::Fileconfig(core::filesystem::config_path() / default_filename)
    {

    }

    std::map<std::string, core::Config*> m_configs;
    
    bool m_testnet;
    std::vector<std::string> m_networks;
    float m_fee;

};

} // namespace c2pool