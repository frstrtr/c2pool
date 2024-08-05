#include <iostream>

#include <boost/asio.hpp>

#include <core/settings.hpp>

#include <impl/ltc/coin/rpc.hpp>
#include <impl/ltc/config.hpp>
#include <impl/ltc/coin/node.hpp>

void check_config(ltc::Config *cfg)
{
    // coin
    
    std::cout << cfg->coin()->m_p2p.address.to_string() << std::endl;
    std::cout << HexStr(cfg->coin()->m_p2p.prefix) << std::endl;
    std::cout << cfg->coin()->m_rpc.address.to_string() << std::endl;
    std::cout << cfg->coin()->m_share_period << std::endl;

    // pool
    std::cout << HexStr(cfg->pool()->m_prefix) << std::endl;
    std::cout << cfg->pool()->m_worker << std::endl;
}

int main()
{
    core::log::Logger::init();

    auto* context = new boost::asio::io_context();
    
    auto settings = core::Fileconfig::load_file<core::Settings>();
    auto config = ltc::Config::load(*settings->m_networks.begin());

    auto* node = new ltc::coin::Node<ltc::Config>(context, config);
    // boost::asio::post(*context, [&]{
        node->run();
    // });   


    // ltc::coin::RPC* rpc = new ltc::coin::RPC();
    // std::cout << rpc->Send("asdasd") << std::endl;

    // boost::asio::steady_timer timer(*context, std::chrono::seconds(10));
    // timer.async_wait([](const auto& ec) { std::cout << "timer end!" << std::endl; });

    context->run();
}