#pragma once

#include <btclibs/uint256.h>

#include <string>
#include <memory>
#include <tuple>
#include <vector>
#include <map>

using std::shared_ptr, std::string;
using std::vector, std::tuple, std::map;

namespace c2pool::shares::share
{
    class BaseShare
    {
    public:
        uint256 max_target;
        uint256 target;
        unsigned int timestamp;
        uint256 previous_hash;

        //TODO:
        //template for new_script: p2pool->test->bitcoin->test_data->test_tx_hash()[34;38 lines]
        //auto /*TODO: char[N], where N = len('\x76\xa9' + ('\x14' + pack.IntType(160).pack(pubkey_hash)) + '\x88\xac') */ new_script;

        unsigned long long desired_version;
        unsigned long absheight;
        uint128 abswork;
        uint256 gentx_hash; //check_hash_link
        //TODO: c2pool::shares::Header header;
        uint256 pow_hash; //litecoin_scrypt->sctyptmodule.c->scrypt_getpowhash
        uint256 hash;
        uint256 header_hash;
        std::vector<uint256> new_transaction_hashes; //TODO: ShareInfoType && shared_ptr<vector<uint256>>?
        unsigned int time_seen;
    };
} // namespace c2pool::shares::share