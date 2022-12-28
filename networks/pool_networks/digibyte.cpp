#include <networks/network.h>
#include <btclibs/uint256.h>
#include <btclibs/util/strencodings.h>
#include <libdevcore/stream_types.h>

#include <vector>
#include <string>
#include <tuple>
#include <memory>
using std::shared_ptr;

namespace c2pool
{
//    DigibyteNetwork::DigibyteNetwork(std::shared_ptr<coind::ParentNetwork> _parent) : Network("DGB", _parent)
//    {
//		SOFTFORKS_REQUIRED = {"nversionbips", "csv", "segwit", "reservealgo", "odo"};
//        BOOTSTRAP_ADDRS = {
//            //CREATE_ADDR("217.72.4.157", "5024")
////            CREATE_ADDR("217.72.6.241", "5024")
////            CREATE_ADDR("p2p-spb.xyz", "5025")
////            CREATE_ADDR("217.42.4.157", "5025")
//            //"217.42.4.157:5025"
//            //CREATE_ADDR("192.168.10.10", "5024")
//                CREATE_ADDR("217.72.4.157", "5024")
////				CREATE_ADDR("80.65.23.139", "5026")
////				CREATE_ADDR("5.188.104.245", "5025")
//        };
//        PREFIX_LENGTH = 8;
//        PREFIX = new unsigned char[PREFIX_LENGTH]{0x83, 0xE6, 0x5D, 0x2C, 0x81, 0xBF, 0x6D, 0x68};
//        IDENTIFIER_LENGHT = 8;
//        IDENTIFIER = new unsigned char[IDENTIFIER_LENGHT]{0x83, 0xE6, 0x5D, 0x2C, 0x81, 0xBF, 0x6D, 0x66};
//
//        MINIMUM_PROTOCOL_VERSION = 1600;
//        SEGWIT_ACTIVATION_VERSION = 17;
//        TARGET_LOOKBEHIND = 200;
//        SHARE_PERIOD = 25;
//        BLOCK_MAX_SIZE = 1000000;
//        BLOCK_MAX_WEIGHT = 4000000;
//        REAL_CHAIN_LENGTH = 24 * 60 * 60 / 10;
//        CHAIN_LENGTH = 24 * 60 * 60 / 10;
//        SPREAD = 30;
//        ADDRESS_VERSION = 30;
//        PERSIST = true;
//
//        MIN_TARGET.SetHex("0");
//        MAX_TARGET.SetHex("fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"); // 2**256/2**20 - 1
//
//        DONATION_SCRIPT = ParseHex("5221038ab82f3a4f569c4571c483d56729e83399795badb32821cab64d04e7b5d106864104ffd03de44a6e11b9917f3a29f9443283d9871c9d743ef30d5eddcd37094b64d1b3d8090496b53256786bf5c82932ec23c3b74d9f05a6f95a8b5529352656664b410457a337b86557f5b15c94544ad267f96a582dc2b91e6873968ff7ba174fda6874af979cd9af41ec2032dfdfd6587be5b14a4355546d541388c3f1555a67d11c2d53ae");
//
//        // init gentx_before_refhash
//        {
//            PackStream gentx_stream;
//
//            StrType dnt_scpt(DONATION_SCRIPT);
//            gentx_stream << dnt_scpt;
//
//            IntType(64) empty_64int(0);
//            gentx_stream << empty_64int;
//
//            PackStream second_str_stream(std::vector<unsigned char>{0x6a, 0x28});
//            IntType(256) empty_256int(uint256::ZERO);
//            second_str_stream << empty_256int;
//            second_str_stream << empty_64int;
//
//            PackStream for_cut;
//            StrType second_str(second_str_stream.data);
//            for_cut << second_str;
//            for_cut.data.erase(for_cut.data.begin() + 3 , for_cut.data.end());
//
//            gentx_stream << for_cut;
//            gentx_before_refhash = gentx_stream.data;
//        }
//    }
} // namespace c2pool