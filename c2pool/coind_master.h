#pragma once

#include <string>
#include <memory>
#include <thread>
#include <vector>

#include <libdevcore/config.h>
#include <libdevcore/logger.h>
#include <libdevcore/common.h>
#include <networks/network.h>
#include <sharechains/share_tracker.h>
#include <boost/asio/thread_pool.hpp>
#include <boost/asio/post.hpp>
using namespace c2pool::dev;
using namespace shares;

#include <boost/program_options.hpp>
namespace po = boost::program_options;

#include "node_manager.h"

namespace c2pool::master
{

    std::shared_ptr<NodeManager> make_node(boost::asio::thread_pool &thread_pool, const std::string &name, const std::shared_ptr<WebServer>& web)
    {
        LOG_INFO << "Starting " << name << " initialization...";

        //Networks/Configs
        LOG_INFO << name << " network initialization...";
        auto net = c2pool::load_network_file(name);
        LOG_INFO << name << " config initialization...";
        auto cfg = c2pool::dev::load_config_file(name);//std::make_shared<c2pool::dev::coind_config>(name);
        LOG_INFO << "web server initialization...";
        auto root = web->get_web_root();
        //------> new net in web_root
        auto web_net = root->new_net(name);
        net->set_web(web_net);
        web_net->add("uptime_begin", c2pool::dev::timestamp());


        //NodeManager
        LOG_INFO << name << " NodeManager initialization...";
        auto node = std::make_shared<NodeManager>(net, cfg, web);

        //run manager in another thread from thread_pool.
        boost::asio::post(thread_pool, [&]() { node->run(); });

        while (!node->is_loaded()) {
            using namespace chrono_literals;
            std::this_thread::sleep_for(100ms);
        }
        LOG_INFO << name << " started!";
        return std::move(node);
    }

    std::vector<std::shared_ptr<NodeManager>> make_nodes(boost::asio::thread_pool &thread_pool, po::variables_map &vm, const std::shared_ptr<WebServer>& web)
    {
        if (vm.count("networks") == 0)
        {
            LOG_ERROR << "Empty network list in args!";
            std::exit(0);
        }

        auto networks = vm["networks"].as<std::vector<std::string>>();
        LOG_INFO.stream() << "Starting with networks: " << networks;

        std::vector<std::shared_ptr<NodeManager>> nodes;
        for (const auto& net : networks)
        {
            nodes.push_back(std::move(make_node(thread_pool, net, web)));
        }
        return std::move(nodes);
    }

    void init_web(const std::shared_ptr<WebServer>& web)
    {
        //---> Create WebRoot
        auto web_root = std::make_shared<WebRoot>(
                [](WebInterface::func_type::argument_type &query)
                {
                });

        //---> Create Index & sub index nodes
        auto index = web_root->get_interface();
        auto status = index->put_child<WebInterface>("status", [](const auto &query)
        {

        });

        //---> Config Status node
//        auto dgb = web_root->new_net("dgb");
//        dgb->set("hashrate", "123123");
//        dgb->set("doa_orphan_rate", "22%");
//        dgb->set("difficulty", "0.1231231223213");
        //------> Pool Rate
        status->put_child<WebNetJson>("pool_rate",
                                      web_root->net_functor(),
                                      [&](const WebNetJson::net_field &net, const auto &query)
                                      {
                                          return net->get("pool").dump();
                                      });
        //------> NodeUptime
        status->put_child<WebNetJson>("node_uptime",
                                      web_root->net_functor(),
                                      [&](const WebNetJson::net_field &net, const auto &query)
                                      {
                                          json j
                                                  {
                                                          {"uptime", c2pool::dev::timestamp() - net->get<int>("uptime_begin")},
                                                          {"peers",  net->get("peers")}
                                                  };
                                          return j.dump();
                                      });
        //------> LocalRate
        status->put_child<WebNetJson>("local_rate",
                                      web_root->net_functor(),
                                      [&](const WebNetJson::net_field &net, const auto &query)
                                      {
                                          return net->get("local").dump();
                                      });
        //------> Shares
        status->put_child<WebNetJson>("shares",
                                      web_root->net_functor(),
                                      [&](const WebNetJson::net_field &net, const auto &query)
                                      {
                                          return net->get("shares").dump();
                                      });

        //------> Payout
        status->put_child<WebNetJson>("payout",
                                      web_root->net_functor(),
                                      [&](const WebNetJson::net_field &net, const auto &query)
                                      {
                                          arith_uint288 attempts_to_block;
                                          attempts_to_block.SetHex(net->get("local")["attempts_to_block"]);

                                          arith_uint288 pool_hash_rate;
                                          pool_hash_rate.SetHex(net->get("pool")["rate"]);

                                          json j
                                                  {
                                                          {"time_to_block", nullptr},
                                                          {"block_value", net->get("local")["block_value"]}
                                                  };

                                          if (!pool_hash_rate.IsNull())
                                              j["time_to_block"] = (attempts_to_block/pool_hash_rate).GetLow64();

                                          return j.dump();
                                      });
        //------> LastBlock
        status->put_child<WebNetJson>("last_block",
                                      web_root->net_functor(),
                                      [&](const WebNetJson::net_field &net, const auto &query)
                                      {
                                          json j
                                                  {
                                                  };
                                          return j.dump();
                                      });
        //------> AddrsAmount
        status->put_child<WebNetJson>("addrs_amount",
                                      web_root->net_functor(),
                                      [&](const WebNetJson::net_field &net, const auto &query)
                                      {
                                          json j
                                                  {
                                                  };
                                          return j.dump();
                                      });
        //------> MinersHasharate
        status->put_child<WebNetJson>("miners_hashrate",
                                      web_root->net_functor(),
                                      [&](const WebNetJson::net_field &net, const auto &query)
                                      {
                                          json j
                                                  {
                                                  };
                                          return j.dump();
                                      });

        //---> Debug Interface
        auto debug = index->put_child<WebInterface>("debug", [](const auto &query) {});
        //------> NetField keys
        debug->put_child<WebNetJson>("netfield_keys",
                                     web_root->net_functor(),
                                     [&](const WebNetJson::net_field &net, const auto &query)
                                     {
                                         json j = net->fields();
                                         return j.dump();
                                     });

        //---> Finish configure web_root/web_server
        web->add_web_root(web_root);



        //---> New net
//        auto &web_dgb = web_root->new_net("dgb");

    }
}