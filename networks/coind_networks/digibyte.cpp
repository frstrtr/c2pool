#include <networks/network.h>

#include <vector>
#include <string>
#include <tuple>
#include <memory>

#include <btclibs/uint256.h>
// #include <libcoind/jsonrpc/coind.h>
// #include <libcoind/data.h>
#include "dgb/digibyte_subsidy.cpp"

using std::shared_ptr;

namespace coind
{
    DigibyteParentNetwork::DigibyteParentNetwork() : ParentNetwork("DGB")
    {
        PREFIX_LENGTH = 4;
        PREFIX = new unsigned char[PREFIX_LENGTH]{0xfa, 0xc3, 0xb6, 0xda};
        P2P_PORT = 12024;
        ADDRESS_VERSION = 30;
        RPC_PORT = 14024;
        BLOCK_PERIOD = 150;
		DUMB_SCRYPT_DIFF = 1;
    }

    //TODO:
    bool DigibyteParentNetwork::jsonrpc_check()
    {
        // defer.inlineCallbacks(lambda bitcoind: defer.returnValue(
        //     (yield helper.check_block_header(bitcoind, '7497ea1b465eb39f1c8f507bc877078fe016d6fcb6dfad3a64c98dcc6e1e8496')) and # genesis block
        //     (yield bitcoind.rpc_getblockchaininfo())['chain'] != 'test'
        // ))
        //##############################
        // uint256 blockheader;
        // blockheader.SetHex("7497ea1b465eb39f1c8f507bc877078fe016d6fcb6dfad3a64c98dcc6e1e8496");

        // bool check_header = coind->check_block_header(blockheader);
        // auto chain_type = coind->GetBlockChainInfo()["chain"].get_str();
        // return check_header && (chain_type != "test");
        return true;
    }

    bool DigibyteParentNetwork::version_check(int version)
    {
        //lambda v: None if 7170200 <= v else 'DigiByte version too old. Upgrade to 7.17.2 or newer!'
        if (7170200 <= version)
        {
            return true;
        }
        else
        {
            return false;
        }
    }

    uint256 DigibyteParentNetwork::POW_FUNC(PackStream& packed_block_header)
    {
        //TODO: return coind::data::hash256(packed_block_header);
    }

	unsigned long long DigibyteParentNetwork::SUBSIDY_FUNC(int32_t height)
	{
		return GetBlockBaseValue(height);
	}
} // namespace c2pool