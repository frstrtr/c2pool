#include <iostream>

#include <core/settings.hpp>
#include <core/fileconfig.hpp>
#include <fstream>

#include <core/filesystem.hpp>
#include <core/log.hpp>

#include <btclibs/uint256.h>
#include <nlohmann/json.hpp>

#include <pool/impl/ltc/protocol.hpp>

int main(int argc, char *argv[])
{
    c2pool::log::Logger::init();
    // c2pool::log::Logger::add_category("all");

    // std::ofstream fout(c2pool::filesystem::config_path() / "config.yaml");
    // std::cout << c2pool::pool::config::get_default() << std::endl;
    // fout << c2pool::pool::config::get_default();
    // fout.close();

    auto settings = c2pool::Fileconfig::load_file<c2pool::Settings>();

    // std::map<std::string, c2pool::fileconfig*> configs;
    // for (const auto& net : settings->m_networks)
    // {
    //     c2pool::config* config = c2pool::config::load(net);
    //     configs[net] = config;
    // }
    
    // std::cout << cfg->m_fee << std::endl;
    // for (const auto& net : cfg->m_networks)
    //     std::cout << net << std::endl;
    ltc::Protocol* protocol;

    auto ping = ltc::message_ping::make(1, 2, 3);
    std::cout << ping->m_command << ": " << ping->m_data << " " << ping->m_data2 << " " << ping->m_data3 << std::endl;
}