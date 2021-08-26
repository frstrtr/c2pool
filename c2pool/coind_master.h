#include <devcore/config.h>
#include <devcore/logger.h>
#include <devcore/common.h>
#include <libnet/nodeManager.h>
#include <networks/network.h>
#include <sharechains/tracker.h>
using namespace c2pool::dev;
using namespace c2pool::libnet;
using namespace c2pool::shares;

#include <string>
#include <memory>
using namespace std;

namespace c2pool::master
{
    shared_ptr<NodeManager> Make_DGB()
    {
        LOG_INFO << "Starting DGB initialization...";
        //Networks/Configs
        auto DGB_net = std::make_shared<c2pool::DigibyteNetwork>();
        auto DGB_cfg = std::make_shared<c2pool::dev::coind_config>();
        //NodeManager
        auto DGB = std::make_shared<NodeManager>(DGB_net, DGB_cfg);
        //ShareTracker
        auto share_tracker = std::make_shared<ShareTracker>(DGB);

        //run manager
        DGB->run();
        if (DGB)
            LOG_INFO << "DGB started!";
        return DGB;
    }
}