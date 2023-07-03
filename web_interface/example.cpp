#include <iostream>
#include <memory>
#include <sstream>
#include "webserver.h"

int main()
{
    auto ioc = std::make_shared<boost::asio::io_context>();

    // Web Root
    auto web_root = std::make_shared<WebRoot>(
            [](WebInterface::func_type::argument_type& query)
            {
            });

    //---> New net
    auto &web_dgb = web_root->new_net("dgb");

    web_dgb.set("fake_num", "{\"data\":12345}");
    web_dgb.set("test_data", R"({"data":"TEST DATA "})");
    web_dgb.set("test_data_count", "1");

    //---> setting for web_root
    auto index = web_root->get_interface();
//    index->put_child<WebDirectory>("/");
    index->put_child<WebInterface>("test", [&](const auto& query){
        std::cout << "query:\n";
        for (auto &[first, second] : query)
        {
            web_dgb.set(first, second);
            std::cout << "\t" << first << ":" << second << std::endl;
        }
    });

    index->put_child<WebJson>("test_data", [&](const auto& query)
    {
        if (query.count("net") && web_root->exist_net(query.at("net")))
            return web_root->net(query.at("net")).get("test_data");
        else
            throw WebNotFound("net");
    });

    index->put_child<WebJson>("data", [&](const auto& query)
    {
        std::stringstream ss;
        web_dgb.set("test_data_count", std::to_string(std::stoi(web_dgb.get("test_data_count")) +1));
        ss << "{\"" << web_dgb.get("test_data") << "\": " << std::stoi(web_dgb.get("test_data_count")) << "}";

        return ss.str();
    });

    // Web Server
    auto web_server = std::make_shared<WebServer>(ioc, tcp::endpoint{net::ip::make_address("192.168.3.30"), 8083}, web_root);
    web_server->run();

    ioc->run();
}