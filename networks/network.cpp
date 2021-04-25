#include "network.h"
#include <vector>
#include <string>
#include <iostream>
//#include <console.h>
#include <tuple>
using namespace std;

namespace c2pool
{

    Network::Network(std::string name) : net_name(name)
    {
        //TODO
        //LOG_INFO << "Created Network Config.";
    }

} // namespace c2pool::config

namespace coind
{
    ParentNetwork::ParentNetwork(std::string name) : net_name(name)
    {
    }
}
