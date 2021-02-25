#include <devcore/config.h>
#include <devcore/logger.h>
#include <devcore/common.h>
#include <libnet/nodeManager.h>
#include <networks/network.h>
using namespace c2pool::dev;
using namespace c2pool::libnet;

#include <string>
#include <memory>
using namespace std;

namespace c2pool::master
{
    shared_ptr<NodeManager> Make_DGB()
    {
        LOG_INFO << "Starting DGB initialization...";
        auto DGB_net = std::make_shared<c2pool::DigibyteNetwork>();
        auto DGB_cfg = std::make_shared<c2pool::dev::coind_config>();
        auto DGB = std::make_shared<NodeManager>(DGB_net, DGB_cfg);
        DGB->run();
        if (DGB)
            LOG_INFO << "DGB started!";
        return DGB;
    }
}