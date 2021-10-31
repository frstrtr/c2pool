#pragma once

#include <string>
#include <memory>
using namespace std;

#include <libdevcore/config.h>
#include <libdevcore/logger.h>
#include <libdevcore/common.h>
#include <networks/network.h>
#include <sharechains/tracker.h>
#include <boost/asio/thread_pool.hpp>
#include <boost/asio/post.hpp>
using namespace c2pool::dev;
using namespace c2pool::libnet;
using namespace c2pool::shares;

#include "node_manager.h"

namespace c2pool::master
{
    shared_ptr<NodeManager> Make_DGB(boost::asio::thread_pool &thread_pool)
    {
        LOG_INFO << "Starting DGB initialization...";
        //Networks/Configs
        auto DGB_net = std::make_shared<c2pool::DigibyteNetwork>();
        auto DGB_cfg = std::make_shared<c2pool::dev::coind_config>();
        //NodeManager
        auto DGB = std::make_shared<NodeManager>(DGB_net, DGB_cfg);

        //run manager in another thread from thread_pool.
        boost::asio::post(thread_pool, [&]()
                          { DGB->run(); });

        if (DGB) //TODO: check loading
            LOG_INFO << "DGB started!";
        return DGB;
    }
}