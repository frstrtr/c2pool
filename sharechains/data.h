#pragma once
#include <btclibs/uint256.h>
#include "shareTypes.h"
#include "string"
using std::string;

namespace c2pool::shares
{
    uint256 check_hash_link(HashLinkType hash_link, unsigned char* data, string const_ending = "")
    {
        auto extra_length = hash_link.length % (512 / 8);
        //TODO: assert len(hash_link['extra_data']) == max(0, extra_length - len(const_ending))
        auto extra = hash_link.extra_data + const_ending;
        //TODO: 
    }
}