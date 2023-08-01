#include <networks/network.h>

#include <vector>
#include <string>
#include <tuple>
#include <memory>

#include <btclibs/uint256.h>
// #include <libcoind/jsonrpc/coind.h>
#include <libcoind/data.h>
#include "dgb/digibyte_subsidy.cpp"
extern "C" {
	#include "dgb/scrypt.h"
}

using std::shared_ptr;

//namespace coind
//{
//    DigibyteParentNetwork::DigibyteParentNetwork() : ParentNetwork("DGB")
//    {
//        PREFIX_LENGTH = 4;
//        PREFIX = new unsigned char[PREFIX_LENGTH]{0xfa, 0xc3, 0xb6, 0xda};
//        P2P_ADDRESS = "217.72.4.157";
//        P2P_PORT = 12024;
//        ADDRESS_VERSION = 30;
//        RPC_PORT = 14024;
//        BLOCK_PERIOD = 150;
//		DUMB_SCRYPT_DIFF = 1;
//        DUST_THRESHOLD = 0.001e8;
//
//        SANE_TARGET_RANGE_MIN.SetHex("10c6f7a0b5ed8d36b4c7f34938583621fafc8b0079a2834d26f9");
//        SANE_TARGET_RANGE_MAX.SetHex("ffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
//    }

    uint256 SCRYPT_POW_FUNC(PackStream& packed_block_header)
    {
		const char* input = reinterpret_cast<const char*>(packed_block_header.data.data());
		char *output = new char[32]{0};
		scrypt_1024_1_1_256(input, output);

		PackStream converted_output(output, 32);
		IntType(256) res;
		converted_output >> res;
		std::cout << res.get().ToString() << std::endl;
		return res.get();
    }

	unsigned long long DGB_SUBSIDY_FUNC(int32_t height)
	{
		return GetBlockBaseValue(height);
	}
//} // namespace c2pool