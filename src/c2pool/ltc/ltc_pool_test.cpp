#include <iostream>
#include <memory>

#include <core/log.hpp>
#include <core/settings.hpp>
#include <btclibs/util/strencodings.h>

#include <impl/ltc/config.hpp>
#include <impl/ltc/node.hpp>

#include <boost/asio.hpp>

int main(int argc, char *argv[])
{
#ifdef _WIN32
    setlocale(LC_ALL, "Russian");
    SetConsoleOutputCP(866);
#endif

    boost::asio::io_context* context = new boost::asio::io_context();
    // std::vector<std::byte> prefix = {std::byte{0x01}, std::byte{0x02}, std::byte{0x03}, std::byte{0x04}};

    core::log::Logger::init();
    auto settings = core::Fileconfig::load_file<core::Settings>();
    auto config = ltc::Config::load(*settings->m_networks.begin());

    LOG_INFO << "Prefix: " << HexStr(config->m_prefix);

    auto* node = new ltc::Node(context, config);
    node->listen(5555);
    // Node* node = new Node(context, prefix);
    // node->run(5555);
    context->run();
}