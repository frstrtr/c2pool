#include "config.h"
#include <vector>
#include <string>
#include <iostream>
#include <console.h>
#include <tuple>
using namespace std;

namespace c2pool::config
{

    Network::Network()
    {
        LOG_INFO << "Created Network Config.";
    }

    //DigibyteNetwork

    DigibyteNetwork::DigibyteNetwork() : Network()
    {
        BOOTSTRAP_ADDRS = {
            CREATE_ADDR("217.72.6.241", "5025")
            //"217.42.4.157:5025"
        };
        PREFIX_LENGTH = 8;
        PREFIX = new unsigned char[PREFIX_LENGTH]{0x83, 0xE6, 0x5D, 0x2C, 0x81, 0xBF, 0x6D, 0x68};
        IDENTIFIER = new unsigned char[8]{0x83, 0xE6, 0x5D, 0x2C, 0x81, 0xBF, 0x6D, 0x66};
        MINIMUM_PROTOCOL_VERSION = 1600;
    }

} // namespace c2pool::config