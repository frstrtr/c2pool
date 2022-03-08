#include "data.h"
#include "share_types.h"
#include <networks/network.h>

namespace c2pool::shares
{
    bool is_segwit_activated(int version, shared_ptr<Network> net)
    {
        return version >= net->SEGWIT_ACTIVATION_VERSION;
    }

    uint256 check_hash_link(HashLinkType hash_link, unsigned char *data, string const_ending)
    {
        auto extra_length = hash_link.length % (512 / 8);
        //TODO: assert len(hash_link['extra_data']) == max(0, extra_length - len(const_ending))
        auto extra = hash_link.extra_data + const_ending;
        int32_t temp_len = hash_link.extra_data.length() + const_ending.length() - extra_length;
        string extra_sub(extra, temp_len, extra.length() - temp_len); //TODO: test

        //TODO: SHA256 test in p2pool
        //TODO: return pack.IntType(256).unpack(hashlib.sha256(sha256.sha256(data, (hash_link['state'], extra, 8*hash_link['length'])).digest()).digest())
    }
}