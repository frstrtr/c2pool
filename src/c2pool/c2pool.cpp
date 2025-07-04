#include <iostream>
#include <fstream>

#include <core/settings.hpp>
#include <core/fileconfig.hpp>
#include <core/pack.hpp>

#include <core/filesystem.hpp>
#include <core/log.hpp>

#include <core/uint256.hpp>
#include <nlohmann/json.hpp>

int main(int argc, char *argv[])
{
    core::log::Logger::init();
    // core::log::Logger::add_category("all");

    // std::ofstream fout(core::filesystem::config_path() / "config.yaml");
    // std::cout << core::pool::config::get_default() << std::endl;
    // fout << core::pool::config::get_default();
    // fout.close();

    auto settings = core::Fileconfig::load_file<core::Settings>();

    // std::map<std::string, core::fileconfig*> configs;
    // for (const auto& net : settings->m_networks)
    // {
    //     core::config* config = core::config::load(net);
    //     configs[net] = config;
    // }
    
    // std::cout << cfg->m_fee << std::endl;
    // for (const auto& net : cfg->m_networks)
    //     std::cout << net << std::endl;
}