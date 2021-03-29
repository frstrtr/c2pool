#include <networks/network.h>
#include <btclibs/uint256.h>
#include <coind/jsonrpc/coind.h>

#include <vector>
#include <string>
#include <tuple>
#include <memory>
using std::shared_ptr;

namespace c2pool
{
    DigibyteNetwork::DigibyteNetwork() : Network()
    {
        BOOTSTRAP_ADDRS = {
            //CREATE_ADDR("217.72.4.157", "5024")
            CREATE_ADDR("217.72.6.241", "5024")
            //CREATE_ADDR("p2p-spb.xyz", "5025")
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

    bool DigibyteNetwork::jsonrpc_check(shared_ptr<c2pool::coind::jsonrpc::Coind> coind)
    {
        // defer.inlineCallbacks(lambda bitcoind: defer.returnValue(
        //     (yield helper.check_block_header(bitcoind, '7497ea1b465eb39f1c8f507bc877078fe016d6fcb6dfad3a64c98dcc6e1e8496')) and # genesis block
        //     (yield bitcoind.rpc_getblockchaininfo())['chain'] != 'test'
        // ))
        uint256 blockheader;
        blockheader.SetHex("7497ea1b465eb39f1c8f507bc877078fe016d6fcb6dfad3a64c98dcc6e1e8496");

        bool check_header = coind->check_block_header(blockheader);
        auto chain_type = coind->GetBlockChainInfo()["chain"].get_str();
        return check_header && (chain_type != "test");
    }

    bool DigibyteNetwork::version_check(int version)
    {
        //lambda v: None if 7170200 <= v else 'DigiByte version too old. Upgrade to 7.17.2 or newer!'
        if (7170200 <= version){
            return true;
        } else {
            return false;
        }
    }
} // namespace c2pool