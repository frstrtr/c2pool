#include "network.h"
#include <vector>
#include <string>
#include <iostream>
//#include <console.h>
#include <tuple>
using namespace std;

namespace c2pool
{

    Network::Network(std::string name, std::shared_ptr<coind::ParentNetwork> _parent) : net_name(name), parent(_parent)
    {
        LOG_INFO << "Created Network [" << name << "].";
    }

} // namespace c2pool::config

namespace coind
{
    ParentNetwork::ParentNetwork(std::string name) : net_name(name)
    {
    }
}
