#include <iostream>

#include <core/settings.hpp>
#include <core/fileconfig.hpp>
#include <fstream>

#include <core/filesystem.hpp>
#include <core/log.hpp>

#include <core/uint256.hpp>
#include <nlohmann/json.hpp>

#include <impl/ltc/protocol.hpp>
#include <impl/ltc/transaction.hpp>

#include <impl/ltc/share.hpp>

#include <pool/handshake.hpp>
#include <core/socket.hpp>

#include <pool/node.hpp>

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
    // std::cout << ping2->m_command << ": " << ping2->m_data << " " << ping2->m_data2 << " " << ping2->m_data3 << std::endl;
    //
    //
    //
    // ltc::Protocol* protocol;

    // auto ping = ltc::message_ping::make();

    // PackStream stream;
    // stream << *ping;
    // stream.print();

    // auto ping2 = ltc::message_ping::make(stream);
    //
    //
    //
    auto p = ltc::TX_NO_WITNESS;

    pool::Node* node;
}