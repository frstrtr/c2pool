#pragma once

#include <string>
#include <memory>
#include <thread>
#include <vector>
using namespace std;

#include <libdevcore/config.h>
#include <libdevcore/logger.h>
#include <libdevcore/common.h>
#include <networks/network.h>
#include <sharechains/tracker.h>
#include <boost/asio/thread_pool.hpp>
#include <boost/asio/post.hpp>
using namespace c2pool::dev;
using namespace shares;

#include <boost/program_options.hpp>
namespace po = boost::program_options;

#include "node_manager.h"

namespace c2pool::master
{

    std::shared_ptr<NodeManager> make_node(boost::asio::thread_pool &thread_pool, const std::string &name)
    {
        LOG_INFO << "Starting " << name << " initialization...";

        //Networks/Configs
        LOG_INFO << name << " network initialization...";
        auto net = c2pool::load_network_file(name);
        LOG_INFO << name << " config initialization...";
        auto cfg = c2pool::dev::load_config_file(name);//std::make_shared<c2pool::dev::coind_config>(name);

        //NodeManager
        LOG_INFO << name << " NodeManager initialization...";
        auto node = std::make_shared<NodeManager>(net, cfg);

        //run manager in another thread from thread_pool.
        boost::asio::post(thread_pool, [&]() { node->run(); });

        while (!node->is_loaded()) {
            using namespace chrono_literals;
            std::this_thread::sleep_for(100ms);
        }
        LOG_INFO << name << " started!";
        return node;
    }

    std::vector<std::shared_ptr<NodeManager>> make_nodes(boost::asio::thread_pool &thread_pool, po::variables_map &vm)
    {
        if (vm.count("networks") == 0)
        {
            LOG_ERROR << "Empty network list in args!";
            std::exit(0);
        }

        auto networks = vm["networks"].as<std::vector<std::string>>();
        LOG_INFO.stream() << "Starting with networks: " << networks;

        std::vector<std::shared_ptr<NodeManager>> nodes;
        for (const auto& n : networks)
        {
            nodes.push_back(make_node(thread_pool, n));
        }

        return nodes;
    }

//    shared_ptr<NodeManager> Make_DGB(boost::asio::thread_pool &thread_pool, po::variables_map &vm) {
//        LOG_INFO << "Starting DGB initialization...";
//        //Networks/Configs
//        LOG_INFO << "DGB_net initialization...";
//        auto DGB_net = c2pool::load_network_file("dgb");
//        LOG_INFO << "DGB_cfg initialization...";
//        auto DGB_cfg = std::make_shared<c2pool::dev::coind_config>(vm);
//        //NodeManager
//        LOG_INFO << "DGB NodeManager initialization...";
//        auto DGB = std::make_shared<NodeManager>(DGB_net, DGB_cfg);
//
//        //run manager in another thread from thread_pool.
//        boost::asio::post(thread_pool, [&]() { DGB->run(); });
//
//        while (!DGB->is_loaded()) {
//            using namespace chrono_literals;
//            std::this_thread::sleep_for(100ms);
//        }
//        LOG_INFO << "DGB started!";
//        return DGB;
//    }
}