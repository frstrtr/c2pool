#include <networks/network.h>
#include <btclibs/uint256.h>

#include <vector>
#include <string>
#include <tuple>

namespace c2pool
{
    DigibyteNetwork::DigibyteNetwork() : Network()
    {
        BOOTSTRAP_ADDRS = {
            CREATE_ADDR("217.72.6.241", "5024")
            //CREATE_ADDR("217.42.4.157", "5025")
            //"217.42.4.157:5025"
        };
        PREFIX_LENGTH = 8;
        PREFIX = new unsigned char[PREFIX_LENGTH]{0x83, 0xE6, 0x5D, 0x2C, 0x81, 0xBF, 0x6D, 0x68};
        IDENTIFIER = new unsigned char[8]{0x83, 0xE6, 0x5D, 0x2C, 0x81, 0xBF, 0x6D, 0x68};
        MINIMUM_PROTOCOL_VERSION = 1600;
        SEGWIT_ACTIVATION_VERSION = 17;

        TARGET_LOOKBEHIND = 200;
        SHARE_PERIOD = 25;
        BLOCK_MAX_SIZE = 1000000;
        BLOCK_MAX_WEIGHT = 4000000;
        REAL_CHAIN_LENGTH = 24 * 60 * 60 / 10;
        CHAIN_LENGTH = 24 * 60 * 60 / 10;
        SPREAD = 30;
    }
} // namespace c2pool