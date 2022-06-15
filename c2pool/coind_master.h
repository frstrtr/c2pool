#pragma once

#include <string>
#include <memory>
#include <thread>
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

#include "node_manager.h"

namespace c2pool::master {
    shared_ptr<c2pool::libnet::NodeManager> Make_DGB(boost::asio::thread_pool &thread_pool) {
        LOG_INFO << "Starting DGB initialization...";
        //Networks/Configs
        LOG_INFO << "DGB_parent_net initialization...";
        auto DGB_parent_net = std::make_shared<coind::DigibyteParentNetwork>();
        LOG_INFO << "DGB_net initialization...";
        auto DGB_net = std::make_shared<c2pool::DigibyteNetwork>(DGB_parent_net);
        LOG_INFO << "DGB_cfg initialization...";
        auto DGB_cfg = std::make_shared<c2pool::dev::coind_config>();
        //NodeManager
        LOG_INFO << "DGB NodeManager initialization...";
        auto DGB = std::make_shared<c2pool::libnet::NodeManager>(DGB_net, DGB_parent_net, DGB_cfg);

        //run manager in another thread from thread_pool.
        boost::asio::post(thread_pool, [&]() { DGB->run(); });

        while (!DGB->is_loaded()) {
            using namespace chrono_literals;
            std::this_thread::sleep_for(100ms);
        }
        LOG_INFO << "DGB started!";
        return DGB;
    }
}