#include <networks/network.h>
#include <btclibs/uint256.h>

#include <vector>
#include <string>
#include <tuple>
#include <memory>
using std::shared_ptr;

namespace c2pool
{
    DigibyteNetwork::DigibyteNetwork(std::shared_ptr<coind::ParentNetwork> _parent) : Network("DGB", _parent)
    {
		SOFTFORKS_REQUIRED = {"nversionbips", "csv", "segwit", "reservealgo", "odo"};
        BOOTSTRAP_ADDRS = {
            //CREATE_ADDR("217.72.4.157", "5024")
//            CREATE_ADDR("217.72.6.241", "5024")
            //CREATE_ADDR("p2p-spb.xyz", "5025")
            //CREATE_ADDR("217.42.4.157", "5025")
            //"217.42.4.157:5025"
            //CREATE_ADDR("192.168.10.10", "5024")
                CREATE_ADDR("217.72.4.157", "5024")
        };
        PREFIX_LENGTH = 8;
        PREFIX = new unsigned char[PREFIX_LENGTH]{0x83, 0xE6, 0x5D, 0x2C, 0x81, 0xBF, 0x6D, 0x68};
        IDENTIFIER_LENGHT = 8;
        IDENTIFIER = new unsigned char[IDENTIFIER_LENGHT]{0x83, 0xE6, 0x5D, 0x2C, 0x81, 0xBF, 0x6D, 0x68};
        MINIMUM_PROTOCOL_VERSION = 1600;
        SEGWIT_ACTIVATION_VERSION = 17;

        TARGET_LOOKBEHIND = 200;
        SHARE_PERIOD = 25;
        BLOCK_MAX_SIZE = 1000000;
        BLOCK_MAX_WEIGHT = 4000000;
        REAL_CHAIN_LENGTH = 24 * 60 * 60 / 10;
        CHAIN_LENGTH = 24 * 60 * 60 / 10;
        SPREAD = 30;
        ADDRESS_VERSION = 30;
        PERSIST = true;

        MIN_TARGET.SetHex("0");
        MAX_TARGET.SetHex("fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"); // 2**256/2**20 - 1
    }
} // namespace c2pool