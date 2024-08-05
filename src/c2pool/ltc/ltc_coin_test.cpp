#include <iostream>

#include <boost/asio.hpp>

#include <core/settings.hpp>

#include <impl/ltc/coin/rpc.hpp>
#include <impl/ltc/config.hpp>
#include <impl/ltc/coin/node.hpp>
#include <impl/ltc/coin/p2p_messages.hpp> // todo: remove

int main()
{
    core::log::Logger::init();

    auto* context = new boost::asio::io_context();
    
    auto settings = core::Fileconfig::load_file<core::Settings>();
    auto config = ltc::Config::load(*settings->m_networks.begin());
    
    // auto* node = new ltc::coin::p2p::NodeP2P<ltc::Config>(context, config);
    // boost::asio::post(*context, [&]{ node->connect(NetService("217.72.4.157", 19335)); }); // 9333

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