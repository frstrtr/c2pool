#pragma once

#include <vector>
#include <string>
#include <map>

#include <core/fileconfig.hpp>

namespace YAML
{
    class Node;
}

namespace c2pool
{

class settings : public fileconfig
{
    static constexpr const char* default_filename = "settings.yaml";

private:
    void parse_network_config(std::string name, YAML::Node& node);

protected:
    std::string get_default() override;
    void load() override;

public:
    settings() 
        : c2pool::fileconfig(c2pool::filesystem::config_path() / default_filename)
    {

    }

    bool m_testnet;
    std::vector<std::string> m_networks;
    float m_fee;

};

} // namespace c2pool